--[[

ZAPRET CAP : nfqws1 desync variants that zapret-antidpi.lua does not implement

--lua-init=@zapret-lib.lua --lua-init=@zapret-antidpi.lua --lua-init=@zapret-cap.lua

]]


-- nfqws1 : "--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=altorder=1"
-- send order : before_host, fake host, after_host, real host. no second fake unlike "hostfakesplit".
-- standard args : direction, payload, fooling, ip_id, rawsend, reconstruct. FOOLING AND REPEATS APPLIED ONLY TO FAKES.
-- arg : host=<str> - hostname template. generate hosts like "random.template". example : e8nzn.vk.com
-- arg : nodrop - do not drop current dissect
function hostfakesplit_alt(ctx, desync)
	if not desync.dis.tcp then
		-- do not cutoff on related icmp
		if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
		return
	end
	direction_cutoff_opposite(ctx, desync)
	local data = desync.reasm_data or desync.dis.payload
	if #data>0 and direction_check(desync) and payload_check(desync) then
		if replay_first(desync) then
			local pos = resolve_range(data, desync.l7payload, "host,endhost-1", true)
			if pos then
				if b_debug then DLOG("hostfakesplit_alt: resolved host range: "..table.concat(zero_based_pos(pos)," ")) end

				-- do not apply fooling to original parts except tcp_ts_up but apply ip_id
				local opts_orig = {rawsend = rawsend_opts_base(desync), reconstruct = {}, ipfrag = {}, ipid = desync.arg, fooling = {tcp_ts_up = desync.arg.tcp_ts_up}}
				local opts_fake = {rawsend = rawsend_opts(desync), reconstruct = reconstruct_opts(desync), ipfrag = {}, ipid = desync.arg, fooling = desync.arg}

				local before = string.sub(data,1,pos[1]-1)
				if b_debug then DLOG("hostfakesplit_alt: sending before_host part 0-"..(pos[1]-2).." len="..#before.." : "..hexdump_dlog(before)) end
				if not rawsend_payload_segmented(desync,before,0,opts_orig) then return VERDICT_PASS end

				local fakehost = genhost(pos[2]-pos[1]+1, desync.arg.host)
				if b_debug then DLOG("hostfakesplit_alt: sending fake host part "..(pos[1]-1).."-"..(pos[2]-1).." len="..#fakehost.." : "..hexdump_dlog(fakehost)) end
				if not rawsend_payload_segmented(desync,fakehost,pos[1]-1,opts_fake) then return VERDICT_PASS end

				local after = string.sub(data,pos[2]+1)
				if b_debug then DLOG("hostfakesplit_alt: sending after_host part "..pos[2].."-"..(#data-1).." len="..#after.." : "..hexdump_dlog(after)) end
				if not rawsend_payload_segmented(desync,after,pos[2],opts_orig) then return VERDICT_PASS end

				local host = string.sub(data,pos[1],pos[2])
				if b_debug then DLOG("hostfakesplit_alt: sending real host part "..(pos[1]-1).."-"..(pos[2]-1).." len="..#host.." : "..hexdump_dlog(host)) end
				if not rawsend_payload_segmented(desync,host,pos[1]-1,opts_orig) then return VERDICT_PASS end

				replay_drop_set(desync)
				return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
			else
				DLOG("hostfakesplit_alt: host range cannot be resolved")
			end
		else
			DLOG("hostfakesplit_alt: not acting on further replay pieces")
		end
		-- drop replayed packets if reasm was sent successfully in splitted form
		if replay_drop(desync) then
			return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
		end
	end
end


--[[
ByeDPI tricks ported from the Android version (profiles "vpn tlsrec", "vpn disorder", "vpn oob").

ByeDPI is a proxy and may change the length of the stream at will. nfqws2 only rewrites packets of a connection
it does not own, so adding bytes needs the trick zapret-antidpi "oob" uses: the outgoing sequence is shifted left
right from the SYN, the inserted bytes then fill the gap, and the server's acks match the client's kernel again.
That is why the function must see the connection from the SYN. Profiles with a hostlist get it only with
--ipcache-hostname, from the second connection to the same address. Started later, the function falls back to a
plain TCP cut at the same position.

standard args : rawsend, ipid
arg : tlsrec=<marker> - split the TLS record of a ClientHello in two at this position (adds 5 bytes)
arg : oob=<marker> - insert one OOB byte at this position (adds 1 byte)
arg : char - OOB byte, "a" by default like ByeDPI
arg : cut=<marker> - also cut TCP here (original payload coordinates). by default right after the inserted bytes
arg : disorder - send the second part first
arg : finish - never start the shift, only complete one started in another profile.
      a connection may jump to another profile when its host name becomes known, and a shifted connection
      that loses the function is broken. put such an instance into a last catch-all profile
]]
local ZC_SHIFT = "zc_byedpi_shift"

local function zc_tls_record_split(data, ins)
	-- ins : 1-based index of the first byte of the second record body
	if #data < 6 or string.byte(data, 1) ~= 0x16 then return nil end
	local reclen = string.byte(data, 4) * 256 + string.byte(data, 5)
	if #data < 5 + reclen or reclen < 2 then return nil end
	if ins <= 6 or ins > 5 + reclen then
		-- marker outside the first record : cut its body in the middle
		ins = 6 + math.floor(reclen / 2)
	end
	local first = ins - 6
	local hdr = string.sub(data, 1, 3)
	return hdr .. bu16(first) .. string.sub(data, 6, ins - 1) .. hdr .. bu16(reclen - first) .. string.sub(data, ins), ins
end

function zc_byedpi(ctx, desync)
	if not desync.track then return end
	if not desync.dis.tcp then
		if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
		return
	end
	local state = desync.track.lua_state
	local mode = desync.arg.tlsrec and "tlsrec" or desync.arg.oob and "oob" or nil
	local delta = mode == "tlsrec" and 5 or mode == "oob" and 1 or 0
	if state[ZC_SHIFT] == nil then
		if not desync.arg.finish and delta > 0 and bitand(desync.dis.tcp.th_flags, TH_SYN + TH_ACK) == TH_SYN then
			-- isn : sequence of the shifted SYN on the wire. limit : after the first payload is sent, acks past
			-- the inserted bytes already match the client's kernel and must stay as they are
			state[ZC_SHIFT] = { delta = delta, mode = mode, marker = desync.arg.tlsrec or desync.arg.oob,
				isn = u32add(desync.dis.tcp.th_seq, -delta) }
			DLOG("zc_byedpi: shifting the connection by "..delta.." for "..mode)
		else
			state[ZC_SHIFT] = false
		end
	end
	local shift = state[ZC_SHIFT]
	if desync.arg.finish and not shift then
		instance_cutoff_shim(ctx, desync)
		return
	end
	-- the connection may have been shifted by an instance of another profile
	if shift then
		delta, mode = shift.delta, shift.mode
	end

	if not desync.outgoing then
		if not shift then return end
		-- zapret-antidpi "oob" checks the reverse position here, but it counts from the client's own SYN:
		-- with a shift of more than 1 byte the server's first ack looks negative there. count from the wire SYN
		local rel = u32add(desync.dis.tcp.th_ack, -shift.isn)
		if shift.limit and rel >= shift.limit then
			instance_cutoff_shim(ctx, desync)
			return
		end
		desync.dis.tcp.th_ack = u32add(desync.dis.tcp.th_ack, delta)
		return VERDICT_MODIFY
	end

	local pos = pos_get(desync, 's', false)
	if shift and pos <= 1 then
		desync.dis.tcp.th_seq = u32add(desync.dis.tcp.th_seq, -delta)
	end
	if pos == 0 then
		return shift and VERDICT_MODIFY or nil
	end
	if pos > 1 then
		-- with a shift the incoming acks may still need fixing: stop only the outgoing side
		local dir = shift and true or nil
		if desync.replay then
			if desync.replay_piece_last then instance_cutoff_shim(ctx, desync, dir) end
			return VERDICT_DROP
		end
		instance_cutoff_shim(ctx, desync, dir)
		return
	end
	local data = desync.reasm_data or desync.dis.payload
	if #data == 0 then
		return shift and VERDICT_MODIFY or nil
	end

	local marker = shift and shift.marker or desync.arg.tlsrec or desync.arg.oob or "host+1"
	local ins = resolve_pos(data, desync.l7payload, marker) or 2
	local out = data
	local cut, urg
	if shift and mode == "tlsrec" then
		local split
		split, ins = zc_tls_record_split(data, ins)
		if not split then
			-- the shift is already done, so the 5 bytes have to go somewhere. a non-TLS stream breaks anyway
			DLOG("zc_byedpi: not a TLS record, the connection will break")
			split = string.sub(data, 1, ins - 1) .. string.rep("\0", 5) .. string.sub(data, ins)
		end
		out = split
		cut = ins
	elseif shift and mode == "oob" then
		local char = desync.arg.char or "a"
		out = string.sub(data, 1, ins - 1) .. char .. string.sub(data, ins)
		urg = ins
		cut = ins + 1
	else
		cut = ins
	end
	if desync.arg.cut then
		local c = resolve_pos(data, desync.l7payload, desync.arg.cut)
		if c then cut = (shift and c >= ins) and c + delta or c end
	end
	if cut <= 1 or cut > #out then cut = nil end

	local parts = {}
	if cut then
		parts[1] = { from = 1, payload = string.sub(out, 1, cut - 1) }
		parts[2] = { from = cut, payload = string.sub(out, cut) }
		if desync.arg.disorder then parts[1], parts[2] = parts[2], parts[1] end
	else
		parts[1] = { from = 1, payload = out }
	end
	DLOG("zc_byedpi: "..(shift and mode or "cut only").." len "..#data.." => "..#out..", cut "..tostring(cut and cut - 1))
	for _, part in ipairs(parts) do
		local dis = deepcopy(desync.dis)
		dis.payload = part.payload
		dis.tcp.th_seq = u32add(desync.dis.tcp.th_seq, part.from - 1)
		if urg and urg >= part.from and urg < part.from + #part.payload then
			dis.tcp.th_flags = bitor(dis.tcp.th_flags, TH_URG)
			dis.tcp.th_urp = urg - part.from + 1
		end
		if not rawsend_dissect_segmented(desync, dis) then
			instance_cutoff_shim(ctx, desync)
			return
		end
	end
	if shift then
		-- the bytes in front of the inserted ones still need the shift in the server's acks
		shift.limit = ins + delta
		-- incoming acks are still to be fixed, so only the outgoing side is done
		if not desync.replay then instance_cutoff_shim(ctx, desync, true) end
	elseif not desync.replay then
		instance_cutoff_shim(ctx, desync)
	end
	return VERDICT_DROP
end
