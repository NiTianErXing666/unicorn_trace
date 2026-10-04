package com.example.testtrace;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("testtarget");
        System.loadLibrary("testtrace");
    }

    private TextView out;
    private ScrollView scroll;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        out = findViewById(R.id.output);
        scroll = findViewById(R.id.scroll);

        Button btnInit = findViewById(R.id.btn_init);
        Button btnTests = findViewById(R.id.btn_tests);
        Button btnInvoke = findViewById(R.id.btn_invoke);
        EditText editAddr = findViewById(R.id.edit_addr);
        EditText editArgs = findViewById(R.id.edit_args);

        btnInit.setOnClickListener(v -> append(nativeInfo()));
        btnTests.setOnClickListener(v -> runTests());

        btnInvoke.setOnClickListener(v -> {
            try {
                nativeInit();
                long addr = Long.decode(editAddr.getText().toString().trim());
                String argStr = editArgs.getText().toString().trim();
                long[] args = new long[0];
                if (!argStr.isEmpty()) {
                    String[] parts = argStr.split(",");
                    args = new long[parts.length];
                    for (int i = 0; i < parts.length; i++)
                        args[i] = Long.decode(parts[i].trim());
                }
                long[] regs = nativeInvoke(addr, args);
                StringBuilder sb = new StringBuilder("invoke(0x");
                sb.append(Long.toHexString(addr)).append(") x0=");
                sb.append(String.format("0x%x (%d)", regs[0], regs[0]));
                for (int i = 1; i < 8; i++)
                    sb.append(String.format(" x%d=0x%x", i, regs[i]));
                sb.append("\ntrace:\n").append(nativeGetTrace());
                append(sb.toString());
            } catch (Exception e) {
                append("invoke failed: " + e + "\n" + nativeGetError());
            }
        });

        findViewById(R.id.btn_trace0).setOnClickListener(v -> { nativeSetTraceLevel(0); append("trace level 0"); });
        findViewById(R.id.btn_trace1).setOnClickListener(v -> { nativeSetTraceLevel(1); append("trace level 1"); });
        findViewById(R.id.btn_trace2).setOnClickListener(v -> { nativeSetTraceLevel(2); append("trace level 2"); });
        findViewById(R.id.btn_trace3).setOnClickListener(v -> { nativeSetTraceLevel(3); append("trace level 3 (slow)"); });

        Intent i = getIntent();
        if (i != null && i.getBooleanExtra("autotest", false)) {
            runTests();
        }
    }

    private void runTests() {
        append(nativeRunTests());
    }

    private void append(String s) {
        runOnUiThread(() -> {
            out.setText(out.getText() + "\n" + s);
            scroll.post(() -> scroll.fullScroll(ScrollView.FOCUS_DOWN));
        });
    }

    public native int nativeInit();
    public native void nativeSetTraceLevel(int level);
    public native long nativeFindSymbol(String lib, String sym);
    public native long[] nativeInvoke(long address, long[] args);
    public native String nativeGetTrace();
    public native String nativeGetError();
    public native String nativeInfo();
    public native int nativeSetTraceFile(String path);
    public native void nativeSetCallTrace(int enable);
    public native String nativeRunTests();
}
