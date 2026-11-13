package org.zapretcap.app;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * Тестовая сборка: отдаёт журнал пушей приложению, которое выбрали в «Отправить». Только чтение и только этот файл.
 */
public class LogProvider extends ContentProvider {
    static final String AUTHORITY = "org.zapretcap.app.logs";
    static final Uri PUSH_LOG = Uri.parse("content://" + AUTHORITY + "/zapret-cap-push-log.txt");

    @Override
    public boolean onCreate() {
        return true;
    }

    private File file() {
        return PushLog.file(getContext());
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!PUSH_LOG.getPath().equals(uri.getPath())) {
            throw new FileNotFoundException(uri.toString());
        }
        return ParcelFileDescriptor.open(file(), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sortOrder) {
        // мессенджеры спрашивают имя и размер файла перед отправкой
        MatrixCursor cursor = new MatrixCursor(new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
        cursor.addRow(new Object[]{uri.getLastPathSegment(), file().length()});
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        return "text/plain";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] args) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] args) {
        return 0;
    }
}
