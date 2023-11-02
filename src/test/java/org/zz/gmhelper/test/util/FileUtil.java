package org.zz.gmhelper.test.util;

import java.io.IOException;
import java.io.RandomAccessFile;

public class FileUtil {
    public static void writeFile(String filePath, byte[] data) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(filePath, "rw")) {
            raf.write(data);
        }
    }

    public static byte[] readFile(String filePath) throws IOException {
        byte[] data;
        try (RandomAccessFile raf = new RandomAccessFile(filePath, "r")) {
            data = new byte[(int) raf.length()];
            raf.read(data);
            return data;
        }
    }
}
