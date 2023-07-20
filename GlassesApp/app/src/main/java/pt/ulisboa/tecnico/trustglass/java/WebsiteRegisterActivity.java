package pt.ulisboa.tecnico.trustglass.java;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

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
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
    }

    @Override
    public void onClick(View v) {
        WebsiteEntry newEntry = new WebsiteEntry(nameInput.getText().toString(), linkInput.getText().toString());

        Intent resultIntent = new Intent();
        resultIntent.putExtra("name", nameInput.getText().toString());
        resultIntent.putExtra("link", linkInput.getText().toString());
        setResult(Activity.RESULT_OK, resultIntent);
        finish();
    }
}