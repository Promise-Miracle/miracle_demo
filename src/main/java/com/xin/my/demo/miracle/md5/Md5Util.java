package com.xin.my.demo.miracle.md5;

import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author miracle一心
 * date 2019/12/3 14:04
 */

public class Md5Util {
    private static final Logger LOGGER = LoggerFactory.getLogger(Md5Util.class);

    public static String encrypt(String str){
        return DigestUtils.md5Hex(str).toUpperCase();


    }

}
