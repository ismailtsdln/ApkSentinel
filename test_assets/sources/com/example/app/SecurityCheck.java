package com.example.app;

import com.scottyab.rootbeer.RootBeer;
import okhttp3.CertificatePinner;

public class SecurityCheck {
    public void performChecks() {
        // Root Detection
        RootBeer rootBeer = new RootBeer(context);
        if (rootBeer.isRooted()) {
            // handle rooted device
        }

        // SSL Pinning
        CertificatePinner certificatePinner = new CertificatePinner.Builder()
            .add("example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .build();
    }

    public void checkSu() {
        String[] paths = {"/system/bin/su", "/system/xbin/su"};
    }
}
