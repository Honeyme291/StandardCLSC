package Ours;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

public class Ours {



    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (
                FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void main(String[] args) throws Exception {
        String rec = "rec@snnu.edu.com";
        String[] messages = new String[]{"111", "12345678", "01234567890123456789", "7777777777", "123", "1123", "123", "123", "123", "123"};
        String[] users = new String[]{"send@snnu.edu.com", "send1@snnu.edu.com", "send2@snnu.edu.com", "send3@snnu.edu.com", "send4@snnu.edu.com", "send5@snnu.edu.com", "send6@snnu.edu.com", "send7@snnu.edu.com", "send8@snnu.edu.com", "send9@snnu.edu.com"};
        String dir = "E:/java program/standard/database/Ours/";
        String pairingParametersFileName = "E:/java program/standard/database/Ours/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signCryptFileName = dir + "signCrypt.properties";
        for (int i = 0; i < 10; i++) {
            long start = System.currentTimeMillis();
            setup(pairingParametersFileName, publicParameterFileName, mskFileName);
            KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            KeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            signCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);
            Verify(pairingParametersFileName,publicParameterFileName,pkFileName,signCryptFileName,users[i],rec);
            UnSignCyption(pairingParametersFileName,publicParameterFileName,skFileName,signCryptFileName,users[i],rec);
            long end = System.currentTimeMillis();
            System.out.print("运行时间为");
            System.out.println(end - start);

        }
    }

    public static void UnSignCyption(String pairingParametersFileName, String publicParameterFileName, String skFileName, String signCryptFileName, String users, String rec) throws NoSuchAlgorithmException {

        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties skp = loadPropFromFile(skFileName);
        Properties SigC = loadPropFromFile(signCryptFileName);
        String xm = skp.getProperty("x"+rec);
        Element x =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xm)).getImmutable();
        String ym = skp.getProperty("y"+rec);
        Element y =bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xm)).getImmutable();
        String Km = SigC.getProperty("K"+users);
        Element K = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Km)).getImmutable();
        String Tm = SigC.getProperty("T"+users);
        Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Tm)).getImmutable();
        String ci = SigC.getProperty("C"+users);
        Element  C= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ci)).getImmutable();
        byte [] c= C.toBytes();
        byte [] message = new byte[c.length];
        Element Q = K.powZn(x.add(y)).add(T.powZn(y));
        byte [] H_2 =sha1(users+Q.toString());

        for (int j = 0; j < c.length; j++){
            message[j] = (byte)(c[j] ^ H_2[j]);
        }

    }


    private static void Verify(String pairingParametersFileName, String publicParameterFileName, String pkFileName, String signCryptFileName, String users,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties pkp = loadPropFromFile(pkFileName);
        Properties sigC = loadPropFromFile(signCryptFileName);

        //取出发送放的公钥和签名以及TK来验证。

        String signS = sigC.getProperty("sign"+users);

        Element sign = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(signS)).getImmutable();


        String KS = sigC.getProperty("K"+users);

        Element K = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(KS)).getImmutable();
        String TS = sigC.getProperty("T"+users);

        Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TS)).getImmutable();

        String rectX = pkp.getProperty("X"+rec);
        String rectY =pkp.getProperty("Y"+rec);
        Element RX = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectX)).getImmutable();
        Element RY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectY)).getImmutable();

        String sendX = pkp.getProperty("X"+users);
        String sendY =pkp.getProperty("Y"+users);
        Element SX = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendX)).getImmutable();
        Element SY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendY)).getImmutable();

        String CS = sigC.getProperty("C"+users);
        Element C = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(CS)).getImmutable();

        byte[] BH_a = sha1(users+rec+SX.toString()+SY.toString()+RX.toString()+RY.toString()+C.toString()+K.toString()+T.toString());
        Element H_3=bp.getZr().newElementFromHash(BH_a,0,BH_a.length).getImmutable();
        Element H_4=bp.getZr().newElementFromHash(BH_a,0,BH_a.length).getImmutable();
        Element H_5=bp.getZr().newElementFromHash(BH_a,0,BH_a.length).getImmutable();
        byte[] BH_1 = sha1(rec+SX.toString()+SY.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        Element Option = P.powZn(sign);

        Element Option1 = T.powZn(H_3).add(SX.powZn(H_4));
        Element Option2 = (SY.add(P_pub.powZn(H_1))).powZn(H_5);

        Element Option3 = Option1.add(Option2);


    }





    private static void signCrypt(String pairingParametersFileName, String publicParameterFileName, String skFileName, String pkFileName, String messages, String users, String signCryptFileName,String rec) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();

        //发送方的操作

        //首先随机生成两个随机数。
        Element k= bp.getZr().newRandomElement().getImmutable();
        Element t= bp.getZr().newRandomElement().getImmutable();
        Element K = P.powZn(k);
        Element T = P.powZn(t);
        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp = loadPropFromFile(skFileName);

        String rectX = pkp.getProperty("X"+rec);
        String rectY =pkp.getProperty("Y"+rec);
        Element RX = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectX)).getImmutable();
        Element RY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(rectY)).getImmutable();

        String sendX = pkp.getProperty("X"+users);
        String sendY =pkp.getProperty("Y"+users);
        Element SX = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendX)).getImmutable();
        Element SY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sendY)).getImmutable();

        String sendx = skp.getProperty("x"+users);
        String sendy =skp.getProperty("y"+users);

        Element Sx = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sendx)).getImmutable();
        Element Sy = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sendy)).getImmutable();


        byte[] BH_1 = sha1(rec+RX.toString()+RY.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        //Xi.add(Ri.add(P_pub.powZn(h1i))).powZn(t);
        Element Q1 = RX.add(RY.add(P_pub.powZn(H_1))).powZn(k);
        Element Q2 = RY.powZn(t);
        Element Q = Q1.add(Q2);
        byte[] messageByte = messages.getBytes();
        byte[] alpha_hash = sha1(rec+Q.toString());
        byte[] ci = new byte[messageByte.length];
        for (int j = 0; j < messageByte.length; j++){
            ci[j] = (byte)(messageByte[j] ^ alpha_hash[j]);
        }
        Element c = bp.getZr().newElementFromHash(ci,0,ci.length);
//        //签名
        byte[] BH_a = sha1(users+rec+SX.toString()+SY.toString()+RX.toString()+RY.toString()+c.toString()+K.toString()+T.toString());
        Element H_3=bp.getZr().newElementFromHash(BH_a,0,BH_a.length).getImmutable();
        Element H_4=bp.getZr().newElementFromHash(BH_a,0,BH_a.length).getImmutable();
        Element H_5=bp.getZr().newElementFromHash(BH_a,0,BH_a.length).getImmutable();
        Element sign =H_3.mul(t).add(H_4.mul(Sx)).add(H_5.mul(Sy));
                //H_3.mul(t.add(H_4.mul(Sx.add(H_5.mul(Sy)))));

        Element Z = Sx.add(H_5.mul(Sy)).invert();
        //将消息保存下来
        Properties sigC=loadPropFromFile(signCryptFileName);
        sigC.setProperty("T"+users, Base64.getEncoder().encodeToString(T.toBytes()));
        sigC.setProperty("K"+users, Base64.getEncoder().encodeToString(K.toBytes()));
        sigC.setProperty("C"+users, Base64.getEncoder().encodeToString(ci.toString().getBytes()));
        sigC.setProperty("sign"+users, Base64.getEncoder().encodeToString(sign.toBytes()));
        sigC.setProperty("Z"+users, Base64.getEncoder().encodeToString(Z.toBytes()));
        storePropToFile(sigC,signCryptFileName);
    }

    public static void KeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");
        String P_pubistr=publicParams.getProperty("P_pub");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties mskPro = loadPropFromFile(mskFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String s_istr=mskPro.getProperty("s");
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();

        Element x = bp.getZr().newRandomElement().getImmutable();
        Element X = P.powZn(x).getImmutable();
        //将公钥存储起来。
        pkp.setProperty("X"+user,Base64.getEncoder().encodeToString(X.toBytes()));
        skp.setProperty("x"+user,Base64.getEncoder().encodeToString(x.toBytes()));


        //KGC生成私钥
        Element u= bp.getZr().newRandomElement().getImmutable();
        Element Y=P.powZn(u).getImmutable();
        byte[] BH_1 = sha1(user+X.toString()+Y.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        Element y = u.add(H_1.powZn(s)).getImmutable();
        //将公钥对保存下来。
        //生成私钥和公钥对
        //H1不能存储。
        pkp.setProperty("Y"+user,Base64.getEncoder().encodeToString(Y.toBytes()));
        skp.setProperty("y"+user,Base64.getEncoder().encodeToString(y.toBytes()));

        storePropToFile(pkp,pkFileName);
        storePropToFile(skp,skFileName);

    }

    public static void setup(String pairingParametersFileName, String publicParameterFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //设置KGC主私钥s

        Element s = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        storePropToFile(mskProp, mskFileName);

        //设置主公钥K_pub和公开参数
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element P_pub = P.powZn(s).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        storePropToFile(pubProp, publicParameterFileName);
    }

}
