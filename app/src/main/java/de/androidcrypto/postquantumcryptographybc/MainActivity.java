package de.androidcrypto.postquantumcryptographybc;

import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.Provider;
import java.security.Security;


public class MainActivity extends AppCompatActivity {

    TextView textViewConsole;
    String consoleText = "";
    String APPTITLE = "change the application title here";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        textViewConsole = (TextView) findViewById(R.id.textviewConsole);

        Button btnClearConsole = findViewById(R.id.btnClearConsole);
        Button btnRunCode = findViewById(R.id.btnRunCode);

        btnClearConsole.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //
                TextView textViewConsole = (TextView) findViewById(R.id.textviewConsole);
                consoleText = "";
                textViewConsole.setText(consoleText);
            }
        });

        btnRunCode.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                clearConsole();
                runMain();
            }
        });
    }

    public void clearConsole() {
        consoleText = "";
        textViewConsole.setText(consoleText);
        MainActivity.this.setTitle(APPTITLE);
    }

    public void appendConsole(String message) {
        String oldText = textViewConsole.getText().toString();
        String newText = oldText + "\n" + message;
        textViewConsole.setText(newText);
    }

    public void printlnX(String print) {
        consoleText = consoleText + print + "\n";
        textViewConsole.setText(consoleText);
        System.out.println();
    }

    private static String getAndroidVersion() {
        String release = Build.VERSION.RELEASE;
        int sdkVersion = Build.VERSION.SDK_INT;
        return "Android SDK: " + sdkVersion + " (" + release + ")";
    }

    /* ############# your code comes below ####################
       change all code: System.out.println("something");
       to printlnX("something");
     */
    // place your main method here
    private void runMain() {

        // this way for adding bouncycastle to android
        Security.removeProvider("BC");
        // Confirm that positioning this provider at the end works for your needs!
        Security.addProvider(new BouncyCastleProvider());
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        printlnX("Android version: " + getAndroidVersion());
        printlnX("BouncyCastle version: " + getBouncyCastleVersion());
        printlnX("BouncyCastle PQC version: " + getBouncyCastlePqcVersion());

        printlnX("");
        printlnX("see in your console output for results, it may takes some minutes to complete");

        PqcNtruPrimeLKemSo6.main(null);
        /*
        // kem's
        PqcChrystalsKyberKem.main(null);
        PqcClassicMcElieceKem.main(null); // 6 parameter sets to run !
        PqcFrodoKem.main(null); // round 3 candidate
        PqcSaberKem.main(null); // round 3 candidate
        PqcNtruKem.main(null); // round 3 candidate
        PqcSNtruPrimeKem.main(null);
        PqcNtruLPRimeKem.main(null);
        // signatures
        PqcChrystalsDilithiumBcSignature.main(null);
        PqcFalconSignature.main((null));
        PqcSphincsPlusSignature.main(null); // 24 parameter sets to run !
        PqcPicnicSignature.main(null); // round 3 candidate
        PqcRainbowSignature.main(null); // round 3 candidate

         */
    }

    private static String getBouncyCastleVersion() {
        Provider provider = Security.getProvider("BC");
        return String.valueOf(provider.getVersion());
    }

    private static String getBouncyCastlePqcVersion() {
        Provider provider = Security.getProvider("BCPQC");
        return String.valueOf(provider.getVersion());
    }

}