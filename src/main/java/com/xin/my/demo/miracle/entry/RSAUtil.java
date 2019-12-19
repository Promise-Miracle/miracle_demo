package com.xin.my.demo.miracle.entry;

import org.apache.commons.net.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * @author miracle一心
 * date 2019/12/3 11:39
 */

public class RSAUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(RSAUtil.class);

    private static final int RSA_SIZE_1024=1024;

    private static final String ALGORITHM="SWITCHRSA";

    public static void main(String[] args) {
        Map<String,Object> keyPairMap = createKry(RSA_SIZE_1024);
        String publicKeyBase64 = keyPairMap.get("PublicKeyBase64").toString();
       // String privateBase64 = keyPairMap.get("privateBase64").toString();
        System.out.println(String.format("publicKeyBase64:","%s",publicKeyBase64));
     //   System.out.println(String.format("privateKeyBase64:","%s",privateBase64));



    }

    /**
     * 生成RSA密钥对
     * @param keySize
     * @return
     */
    public static Map<String, Object> createKry(int keySize){
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (Exception e) {
            LOGGER.error("初始化密钥异常",e);
            return null;
        }
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey Private = keyPair.getPrivate();
        PublicKey Public = keyPair.getPublic();
        Map map = new HashMap();
        map.put("PublicKey",Public);
        map.put("PrivateKey",Private);
        map.put("PublicKeyBase64", Base64.encodeBase64(Public.getEncoded()));
        map.put("PrivateKeyBase64", Base64.encodeBase64(Private.getEncoded()));
        return map;
    }

    /**
     * 获取公钥Base64 的字符串
     * @param publicKey
     * @return
     */
    public static String getBase64PublicKeyString(PublicKey publicKey){
        return Base64.encodeBase64URLSafeString(publicKey.getEncoded()).trim();
    }

    /**
     * 获取私钥Base64的字符串
     * @param privateKey
     * @return
     */
    public static String getBase64PrivateKeyString(PrivateKey privateKey){
        return Base64.encodeBase64URLSafeString(privateKey.getEncoded()).trim();
    }

    /**
     * 获取公钥
     * @param publicKeyBase64
     * @return
     * @throws Exception
     */
    public static PublicKey getPublicKey(String publicKeyBase64)throws Exception{
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(org.apache.commons.net.util.Base64.decodeBase64(publicKeyBase64));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        return publicKey;
    }

    /**
     * 获取私钥
     * @param privateKeyBase64
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey getPrivateKey(String privateKeyBase64)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(org.apache.commons.net.util.Base64.decodeBase64(privateKeyBase64));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey priKey = keyFactory.generatePrivate(priKeySpec);
        return priKey;
    }

    /**
     * 使用私钥对数据进行签名
     * @param date  要签名的字据
     * @param privateKey 私钥
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] sign(byte[] date,PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature instance = Signature.getInstance(ALGORITHM);
        instance.initSign(privateKey);
        instance.update(date);
        return instance.sign();
    }

    /**
     * 使用私钥对数据进行签名
     * @param data   需要签名的字符串
     * @param privateKey  私钥
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static String sign(String data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return Base64.encodeBase64URLSafeString(sign(data.getBytes(),privateKey)).trim();
    }

    /**
     * 签名校验
     * @param date 参与签名的数据
     * @param sign 数字签名
     * @param publicKey 公钥
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verify(byte[] date,byte[] sign,PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature instance = Signature.getInstance(ALGORITHM);
        instance.initVerify(publicKey);
        instance.update(date);
        return instance.verify(sign);
    }

    /**
     * 签名校验
     * @param data 参与签名的数据
     * @param sign 数据签名
     * @param publicKey 公钥
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verify(String data, String sign,PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return verify(data.getBytes(), Base64.decodeBase64(sign), publicKey);
    }


}
