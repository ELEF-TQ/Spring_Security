package com.eleftq.sec.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Encoders;

public class KeyGenerator {
    public static void main(String[] args) {
        String key = Encoders.BASE64.encode(
                Jwts.SIG.HS512.key().build().getEncoded()
        );
        System.out.println("Secret Key: " + key);
    }
}