package pt.ulisboa.tecnico.trustglass.java;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.AdapterView;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import pt.ulisboa.tecnico.trustglass.R;

public class WebsiteRegisterActivity extends AppCompatActivity implements OnClickListener {
    private EditText nameInput = null;
    private EditText linkInput = null;
    private EditText usernameInput = null;
    private EditText passInput = null;
    private Button applyButton = null;
    private LivePreviewActivity previewActivity = null;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_website_register);

        nameInput = findViewById(R.id.editWebsiteName);
        linkInput = findViewById(R.id.editWebsiteLink);
        linkInput = findViewById(R.id.editUsername);
        linkInput = findViewById(R.id.editPassword);
        applyButton = findViewById(R.id.applyButton);
        applyButton.setOnClickListener(this);

//        textView.setMovementMethod(new ScrollingMovementMethod());
//        textView.setText(getIntent().getStringExtra("qrText"));
    }

    @Override
    protected void onDestroy() {
//        Log.d()
        super.onDestroy();
    }

    @Override
    public void onClick(View v) {
        WebsiteEntry newEntry = new WebsiteEntry(nameInput.getText().toString(), linkInput.getText().toString());

//        connectToTarget();

        Intent resultIntent = new Intent();
        resultIntent.putExtra("name", nameInput.getText().toString());
        resultIntent.putExtra("link", linkInput.getText().toString());
        setResult(Activity.RESULT_OK, resultIntent);
        finish();
    }
}