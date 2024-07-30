package Xu;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Struct;
import java.util.Base64;
import java.util.Properties;

public class Xu {

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

    public static Properties loadPropFromFile(String fileName) throws InterruptedException {
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
        String dir = "E:/java program/standard/database/Xu/";
        String pairingParametersFileName = "E:/java program/standard/database/Xu/a.properties";
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
            PartialKeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            PartialKeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            SetPrivateKey(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            SetPrivateKey(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            SetPublicKey(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            SetPublicKey(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);

            signCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);
            Verify(pairingParametersFileName,publicParameterFileName,pkFileName,signCryptFileName,users[i],rec,messages[i]);
            UnSignCyption(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,signCryptFileName,users[i],rec,messages[i]);
            long end = System.currentTimeMillis();
            System.out.print("运行时间为");
            System.out.println(end - start);

        }
    }

    public static void UnSignCyption(String pairingParametersFileName, String publicParameterFileName, String pkFileName,String skFileName, String signCryptFileName, String users, String rec,String messages) throws NoSuchAlgorithmException, InterruptedException {

        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties skp = loadPropFromFile(skFileName);
        Properties SigC = loadPropFromFile(signCryptFileName);

        String sign1m = SigC.getProperty("sign1"+users);
        Element sign1 =bp.getG2().newElementFromBytes(Base64.getDecoder().decode(sign1m)).getImmutable();

        String sign2m = SigC.getProperty("sign2"+users);
        Element sign2 =bp.getG2().newElementFromBytes(Base64.getDecoder().decode(sign2m)).getImmutable();

        String Vm = SigC.getProperty("V"+users);
        Element V =bp.getG2().newElementFromBytes(Base64.getDecoder().decode(Vm)).getImmutable();

        String SR1 = skp.getProperty("SU"+rec);
        Element SR = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SR1)).getImmutable();

        Element element = bp.pairing(V,P.powZn(SR));

        byte [] Option = element.toBytes();
        byte []sign2p = new byte[messages.length()];

        for (int i=0;i<messages.length();i++){
            sign2p[i] = (byte)(messages.charAt(i) ^ Option[i]);
        }




    }


    private static void Verify(String pairingParametersFileName, String publicParameterFileName, String pkFileName, String signCryptFileName, String users,String rec, String messages) throws NoSuchAlgorithmException, InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties SigC = loadPropFromFile(signCryptFileName);
        Properties pkp = loadPropFromFile(pkFileName);
        String sign1m = SigC.getProperty("sign1"+users);
        Element sign1 =bp.getGT().newElementFromBytes(Base64.getDecoder().decode(sign1m)).getImmutable();

        String sign2m = SigC.getProperty("sign2"+users);
        Element sign2 =bp.getG2().newElementFromBytes(Base64.getDecoder().decode(sign2m)).getImmutable();

        String Vm = SigC.getProperty("V"+users);
        Element V =bp.getG2().newElementFromBytes(Base64.getDecoder().decode(Vm)).getImmutable();

        byte[] BH_1 = sha1(users);
        Element QS=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        byte[] BH_1m = sha1(rec);
        Element QR=bp.getZr().newElementFromHash(BH_1m,0,BH_1m.length).getImmutable();

        String PSm = pkp.getProperty("PU"+users);
        Element PS =bp.getGT().newElementFromBytes(Base64.getDecoder().decode(PSm)).getImmutable();


        byte [] H_3 = sha1(QS.toString()+QR+messages);
        Element element=bp.getZr().newElementFromHash(H_3,0,H_3.length).getImmutable();

        Element option = bp.pairing(V,P.powZn(element)).mul(PS);

    }





    private static void signCrypt(String pairingParametersFileName, String publicParameterFileName, String skFileName, String pkFileName, String messages, String users, String signCryptFileName,String rec) throws NoSuchAlgorithmException, InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();

        //发送方的操作

        //首先随机生成两个随机数。
        Element v= bp.getZr().newRandomElement().getImmutable();

        Element V = P.powZn(v);

        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp = loadPropFromFile(skFileName);


        String SS1 = skp.getProperty("SU"+users);
        Element SS = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(SS1)).getImmutable();

        byte[] BH_1 = sha1(users);
        Element QS=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        byte[] BH_1m = sha1(rec);
        Element QR=bp.getZr().newElementFromHash(BH_1m,0,BH_1m.length).getImmutable();

        byte [] H_3 = sha1(QS.toString()+QR+messages);
        Element element=bp.getZr().newElementFromHash(H_3,0,H_3.length).getImmutable();

        Element sign1 = bp.pairing(P,P.powZn(v.mul(element)));

        String sign2m = pkp.getProperty("PU"+rec);

        Element PR=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sign2m)).getImmutable();

        byte [] Option = PR.toBytes();
        byte []sign2p = new byte[messages.length()];

        for (int i=0;i<messages.length();i++){
            sign2p[i] = (byte)(messages.charAt(i) ^ Option[i]);
        }

        Element sign2 = bp.getZr().newElementFromHash(sign2p,0,sign2p.length);


        //将消息保存下来
        Properties sigC=loadPropFromFile(signCryptFileName);
        sigC.setProperty("V"+users, Base64.getEncoder().encodeToString(V.toBytes()));
        sigC.setProperty("sign1"+users, Base64.getEncoder().encodeToString(sign1.toBytes()));
        sigC.setProperty("sign2"+users, Base64.getEncoder().encodeToString(sign2.toString().getBytes()));
         storePropToFile(sigC,signCryptFileName);
    }

    private static void SetPrivateKey(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException, InterruptedException {
       //在这里。。。。。。。。。。。
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");
        String P_pubistr=publicParams.getProperty("P_pub");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties mskPro = loadPropFromFile(mskFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);

        String xu1 = skp.getProperty("xU"+user);
        Element xU = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xu1)).getImmutable();
        String fu1 = skp.getProperty("fu"+user);
        Element fu = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(fu1)).getImmutable();

        Element SU = xU.mul(fu);
        //将公钥存储起来。
        skp.setProperty("SU"+user,Base64.getEncoder().encodeToString(SU.toBytes()));
        storePropToFile(pkp,pkFileName);
        storePropToFile(skp,skFileName);
    }
    private static void SetPublicKey(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException, InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");
        String P_pubistr=publicParams.getProperty("P_pub");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties mskPro = loadPropFromFile(mskFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);

        String Su1 = skp.getProperty("SU"+user);
        Element SU = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(Su1)).getImmutable();
        Element PU = bp.pairing(P,P.powZn(SU));

        //将公钥存储起来。
        pkp.setProperty("PU"+user,Base64.getEncoder().encodeToString(PU.toBytes()));
        storePropToFile(pkp,pkFileName);
        storePropToFile(skp,skFileName);
    }

    private static void PartialKeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException, InterruptedException {
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


        byte[] BH_1 = sha1(user);
        Element Qu=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        Element fu = s.mul(Qu);
        //将公钥存储起来。
        skp.setProperty("fu"+user,Base64.getEncoder().encodeToString(fu.toBytes()));
        storePropToFile(pkp,pkFileName);
        storePropToFile(skp,skFileName);

    }
    public static void KeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException, InterruptedException {
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

        Element xU = bp.getZr().newRandomElement().getImmutable();
        Element XU = P.powZn(xU).getImmutable();
        //将公钥存储起来。
        pkp.setProperty("XU"+user,Base64.getEncoder().encodeToString(XU.toBytes()));
        skp.setProperty("xU"+user,Base64.getEncoder().encodeToString(xU.toBytes()));

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
        Element E = bp.pairing(P,P);
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        pubProp.setProperty("E", Base64.getEncoder().encodeToString(E.toBytes()));

        storePropToFile(pubProp, publicParameterFileName);
    }
}
