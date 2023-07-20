package pt.ulisboa.tecnico.trustglass.java;

import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import pt.ulisboa.tecnico.trustglass.R;

public class QRTextActivity extends AppCompatActivity {
    private TextView textView = null;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_qr_text);

        textView = findViewById(R.id.textView);
        textView.setMovementMethod(new ScrollingMovementMethod());
        textView.setText(getIntent().getStringExtra("qrText"));
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
    }
}
