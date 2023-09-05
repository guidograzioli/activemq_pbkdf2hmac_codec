/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ansiblemiddleware.amq.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.lang.invoke.MethodHandles;

import org.apache.activemq.artemis.utils.ByteUtil;
import org.apache.activemq.artemis.utils.SensitiveDataCodec;

/**
 * The one-way uses "PBKDF2" hash algorithm
 */
public class PBKDF2WithHmacCodec implements SensitiveDataCodec<String> {

   private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

   public static final String HASHNAME = "hashname";
   public static final String ITERATIONS = "iterations";
   private CodecAlgorithm algorithm;

   @Override
   public String decode(Object secret) throws Exception {
      return algorithm.decode((String) secret);
   }

   @Override
   public String encode(Object secret) throws Exception {
      return algorithm.encode((String) secret);
   }

   @Override
   public void init(Map<String, String> params) throws Exception {
      this.algorithm = new PBKDF2Algorithm(params);
   }

   /**
    * @param args
    * @throws Exception
    */
   public static void main(String[] args) throws Exception {
      if (args.length != 1) {
         System.err.println("Use: java -cp <classPath> com.ansiblemiddleware.amq.utils.PBKDF2WithHmacCodec password-to-encode");
         System.err.println("Error: no password on the args");
         System.exit(-1);
      }
      PBKDF2WithHmacCodec codec = new PBKDF2WithHmacCodec();
      Map<String, String> params = new HashMap<>();
      Properties properties = System.getProperties();
      synchronized (properties) {
         for (final String name : properties.stringPropertyNames()) {
            params.put(name, properties.getProperty(name));
         }
      }
      codec.init(params);
      Object encode = codec.encode(args[0]);

      System.out.println("Encoded password (without quotes): \"" + encode + "\"");
   }

   @Override
   public boolean verify(char[] inputValue, String storedValue) {
      return algorithm.verify(inputValue, storedValue);
   }

   private abstract static class CodecAlgorithm {

      protected Map<String, String> params;

      CodecAlgorithm(Map<String, String> params) {
         this.params = params;
      }

      public abstract String decode(String secret) throws Exception;
      public abstract String encode(String secret) throws Exception;

      public boolean verify(char[] inputValue, String storedValue) {
         return false;
      }
   }

   protected String getFromEnv(final String envVarName) {
      return System.getenv(envVarName);
   }

   public static String envVarNameFromSystemPropertyName(final String systemPropertyName) {
      return systemPropertyName.replace(".","_").toUpperCase(Locale.getDefault());
   }

   private static class PBKDF2Algorithm extends CodecAlgorithm {
      private static final String SEPARATOR = ":";
      private String randomScheme = "SHA1PRNG";
      private String secretKeyAlgorithm = "PBKDF2WithHmacSHA1";
      private int keyLength = 64 * 8;
      private int saltLength = 32;
      private int iterations = 1024;
      private SecretKeyFactory skf;
      private static SecureRandom sr;

      PBKDF2Algorithm(Map<String, String> params) throws NoSuchAlgorithmException {
         super(params);
         if (params.get(HASHNAME) != null) {
            this.secretKeyAlgorithm = "PBKDF2WithHmac" + params.get(HASHNAME).toUpperCase();
         }
         if (params.get(ITERATIONS) != null) {
            this.iterations = Integer.parseInt(params.get(ITERATIONS));
         }
         skf = SecretKeyFactory.getInstance(secretKeyAlgorithm);
         if (sr == null) {
            sr = SecureRandom.getInstance(randomScheme);
         }
      }

      @Override
      public String decode(String secret) throws Exception {
         throw new IllegalArgumentException("Algorithm doesn't support decoding");
      }

      public byte[] getSalt() {
         byte[] salt = new byte[this.saltLength];
         sr.nextBytes(salt);
         return salt;
      }

      @Override
      public String encode(String secret) throws Exception {
         char[] chars = secret.toCharArray();
         byte[] salt = getSalt();

         StringBuilder builder = new StringBuilder();
         builder.append(iterations).append(SEPARATOR).append(ByteUtil.bytesToHex(salt)).append(SEPARATOR);

         PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, keyLength);

         byte[] hash = skf.generateSecret(spec).getEncoded();
         String hexValue = ByteUtil.bytesToHex(hash);
         builder.append(hexValue);

         return builder.toString();
      }

      @Override
      public boolean verify(char[] plainChars, String storedValue) {
         String[] parts = storedValue.split(SEPARATOR);
         int originalIterations = Integer.parseInt(parts[0]);
         byte[] salt = ByteUtil.hexToBytes(parts[1]);
         byte[] originalHash = ByteUtil.hexToBytes(parts[2]);

         PBEKeySpec spec = new PBEKeySpec(plainChars, salt, originalIterations, originalHash.length * 8);
         byte[] newHash;

         try {
            newHash = skf.generateSecret(spec).getEncoded();
         } catch (InvalidKeySpecException e) {
            return false;
         }

         return Arrays.equals(newHash, originalHash);
      }
   }
}