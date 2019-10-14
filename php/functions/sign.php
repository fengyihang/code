<?php

/*
 *  接口签名验证固定参数：
    接口签名验证固定参数是客户端调用所有接口时都需要传递的参数。用于接口版本管理（旧版本的安卓app依然可以使用）、安全校验等目的。
    os    String  客户端操作系统名称  例如"android", "ios"
    uuid  String  移动设备唯一标识符  例如安卓手机的IMEI，苹果手机的UUID
    version  String   客户端版本号   例如"1.0","2.0"（接口设计高版本接口要兼容低版本的接口）
    timestamp  long     客户端调用接口时的时间戳
    signature   String   客户端接口调用签名

    签名算法
     Ps： (可以根据实际变更其他算法使用)
     对除去signature外的所有参数，按参数名的字典顺序排序后计算sha1值。例如，某个接口的参数"mobile=18600933630&verifyCode=135466&os=android&uuid=GB1303EA&version=1.0&timestamp=1442067125464"
      a) 按参数名的字典顺序排序成  "mobile=18600933630os=androidtimestamp=1442067125464uuid=GB1303EAverifyCode=135466version=1.0"
      b) signature值为字符串"mobile=18600933630os=androidtimestamp=1442067125464uuid=GB1303EAverifyCode=135466version=1.0"的sha1值
    注意：简而言之，签名设计的原则就是保证服务器所接收到的数据是自己的APP端传过来的，而不是其他人非法调用的，在APP端给签名加密时需要加上特有固定参数，服务器也是加上特有固定参数，从而来保证一对一的传输，每个接口都需要调用该签名验证方法

 */

/**
 * 签名的验证方法代码
 * @param $args
 * @param $signature
 * @param $signKey "平台给的签名加密字符串"
 * @param string $signtype 'yes':验证，'no'：不验证
 * @return bool
 */
function checkSign($args,$signature,$signKey="",$signtype = 'yes')
{
    // 上线时去除该部分，必须验证签名
    if($signtype == 'no')
    {
        return true;
    }
    if(!$args || !$signature)
    {
        return false;
    }
    // 同一签名调用时间限制
    if (time() - $args['timestamp'] > 300)
    {
        return false;
    }
    $args['xiaoming'] = 'wuyingqi431';  //特有固定参数
    // 按数组的键排序
    ksort($args);

    $sign = '';

    foreach($args as $k => $v)
    {
        $sign .= $k . '=' . $v;
    }
    // 加密
    $sign = sha1($sign . $signKey);
    if($sign == $signature)
    {
        return true;
    }
    return false;
}

// 签名
function sign($data) {
    // 读取私钥文件
    $priKey = file_get_contents('key/rsa_private_key.pem');

    // 转换为openssl密钥，必须是没有经过pkcs8转换的私钥
    $res = openssl_get_privatekey($priKey);

    // 调用openssl内置签名方法，生成签名$sign
    openssl_sign($data, $sign, $res);

    //释放资源
    openssl_free_key($res);

    return $sign;
}

// 验证
function verify($data, $sign)
{
    //读取支付宝公钥文件
    $pubKey = file_get_contents('key/alipay_public_key.pem');

    //转换为openssl格式密钥
    $res = openssl_get_publickey($pubKey);

    //调用openssl内置方法验签，返回bool值
    $result = (bool)openssl_verify($data, $sign, $res);

    //释放资源
    openssl_free_key($res);

    return $result;
}

// 解密
function decrypt($content) {

    //读取商户私钥
    $priKey = file_get_contents('key/rsa_private_key.pem');

    //转换为openssl密钥，必须是没有经过pkcs8转换的私钥
    $res = openssl_get_privatekey($priKey);

    //声明明文字符串变量
    $result = '';

    //循环按照128位解密
    for($i = 0; $i < strlen($content)/128; $i++ ) {
        $data = substr($content, $i * 128, 128);

        //拆分开长度为128的字符串片段通过私钥进行解密，返回$decrypt解析后的明文
        openssl_private_decrypt($data, $decrypt, $res);

        //明文片段拼接
        $result .= $decrypt;
    }

    //释放资源
    openssl_free_key($res);

    //返回明文
    return $result;
}
