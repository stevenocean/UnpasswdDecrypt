package io.github.stevenocean.unpasswddecrypt;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Handler;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class MainActivity extends AppCompatActivity {

    private KeyStore mKeyStore;
    private FingerprintManager mFpManager;
    private byte [] mIV;

    private EditText etPlain;
    private TextView tvEncrypted;
    private TextView tvDecrypted;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            // Register provider
            mKeyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
            finish();
            return;
        }

        // Fingerprint service
        mFpManager = (FingerprintManager) getSystemService(Context.FINGERPRINT_SERVICE);
        if (null == mFpManager) {
            finish();
            return;
        }

        etPlain = findViewById(R.id.plain_et);
        tvEncrypted = findViewById(R.id.encrypted_tv);
        tvDecrypted = findViewById(R.id.decrypted_tv);
    }

    public void generateKey(View view) throws NoSuchProviderException, NoSuchAlgorithmException, IOException, CertificateException, InvalidAlgorithmParameterException {

        // AES + CBC + PKCS7
        final KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        mKeyStore.load(null);
        generator.init(new KeyGenParameterSpec.Builder("FirstWallet",
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setUserAuthenticationRequired(true)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build());

        // Generate (symmetric) key, and store to KeyStore
        final SecretKey sk = generator.generateKey();
        Toast.makeText(this, String.format("Generate key success %s, %s", sk.getAlgorithm(), sk.getFormat()), Toast.LENGTH_LONG).show();
    }

    public void encryptData(View view) throws CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchPaddingException, InvalidKeyException {

        mKeyStore.load(null);
        final SecretKey sk = (SecretKey) mKeyStore.getKey("FirstWallet", null);
        if (null == sk) {
            Toast.makeText(this, "Can not get key", Toast.LENGTH_LONG).show();
            return;
        }

        final Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        cipher.init(Cipher.ENCRYPT_MODE, sk);

        // Need authenticate by fingerprint
        final FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
        mFpManager.authenticate(cryptoObject, null, 0, new FingerprintManager.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(MainActivity.this, "Fp auth error: " + errString, Toast.LENGTH_LONG).show();
            }

            @Override
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                super.onAuthenticationHelp(helpCode, helpString);
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                Toast.makeText(MainActivity.this, "Fp auth succ", Toast.LENGTH_LONG).show();

                // Encrypt data by cipher
                final String plainText = etPlain.getText().toString();
                final Cipher cipher = result.getCryptoObject().getCipher();
                try {
                    byte [] encrypted = cipher.doFinal(plainText.getBytes());
                    mIV = cipher.getIV();
                    final String encryptedWithBase64 = Base64.encodeToString(encrypted, Base64.URL_SAFE);
                    tvEncrypted.setText(encryptedWithBase64);
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(MainActivity.this, "Fp auth failed", Toast.LENGTH_LONG).show();
            }
        }, new Handler());

    }

    public void decryptWithFingerprint(View view) throws CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        mKeyStore.load(null);
        final SecretKey sk = (SecretKey) mKeyStore.getKey("FirstWallet", null);
        if (null == sk) {
            Toast.makeText(this, "Can not get key", Toast.LENGTH_LONG).show();
            return;
        }

        final Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        cipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(mIV));

        // First need authenticate by fingerprint
        final FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
        mFpManager.authenticate(cryptoObject, null, 0, new FingerprintManager.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(MainActivity.this, "Fp auth error: " + errString, Toast.LENGTH_LONG).show();
            }

            @Override
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                super.onAuthenticationHelp(helpCode, helpString);
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                Toast.makeText(MainActivity.this, "Fp auth succ", Toast.LENGTH_LONG).show();

                // Decrypt data by cipher
                final String encryptedWithBase64 = tvEncrypted.getText().toString();
                final byte [] encryptedBytes = Base64.decode(encryptedWithBase64, Base64.URL_SAFE);
                final Cipher cipher = result.getCryptoObject().getCipher();
                try {
                    byte [] decryptedBytes = cipher.doFinal(encryptedBytes);
                    String decryptedText = new String(decryptedBytes);
                    tvDecrypted.setText(decryptedText);
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(MainActivity.this, "Fp auth failed", Toast.LENGTH_LONG).show();
            }
        }, new Handler());
    }
}
