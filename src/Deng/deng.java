package Deng;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Time;
import java.util.Base64;
import java.util.Properties;
import java.util.Timer;

public class deng {

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
        String dir = "E:/java program/standard/database/Deng/";
        String pairingParametersFileName = "E:/java program/standard/database/Deng/a.properties";
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
            signCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);
            Verify(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,signCryptFileName,users[i],rec,messages[i]);
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
        String PE = pubProp.getProperty("E");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Element E = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PE)).getImmutable();

        Properties pkp = loadPropFromFile(pkFileName);
        Properties sigC = loadPropFromFile(signCryptFileName);
        Properties skp = loadPropFromFile(skFileName);

        //取出发送放的公钥和签名以及TK来验证。

        String PW = sigC.getProperty("W"+users);

        Element W = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PW)).getImmutable();

        String Y = pkp.getProperty("Y"+users);
        Element SY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Y)).getImmutable();

        String T = pkp.getProperty("T"+users);
        Element ST = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T)).getImmutable();


        String Y1 = pkp.getProperty("Y"+rec);
        Element RY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Y1)).getImmutable();

        String T1 = pkp.getProperty("T"+rec);
        Element RT = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T1)).getImmutable();


        byte[] BH_1 = sha1(users+SY.toString());
        Element ks=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        String U1 = sigC.getProperty("U"+users);
        Element U = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(U1)).getImmutable();
        String V1 = sigC.getProperty("V"+users);
        Element V = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(V1)).getImmutable();

        String x = skp.getProperty("x"+rec);
        Element Rx = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x)).getImmutable();

        String t = skp.getProperty("t"+rec);
        Element Rt = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(t)).getImmutable();

        byte[] BH_4 = sha1(messages+U.toString()+V.toString()+rec+RY.toString()+RT.toString()+users+SY.toString()+ST.toString());
        Element H_4=bp.getZr().newElementFromHash(BH_4,0,BH_4.length).getImmutable();



        byte[] BH_3 = sha1(U.toString()+V.toString()+rec+RY.toString()+RT.toString()+users+SY.toString()+ST.toString());
        Element g=bp.getZr().newElementFromHash(BH_3,0,BH_3.length).getImmutable();
        byte[] BH_5 = sha1(messages+U.toString()+V.toString()+rec+RY.toString()+RT.toString()+users+SY.toString()+ST.toString());
        Element a=bp.getZr().newElementFromHash(BH_5,0,BH_5.length).getImmutable();

        byte[] messageByte = messages.getBytes();
        byte[] ci = new byte[messageByte.length];
        for (int j = 0; j < messageByte.length; j++){
            ci[j] = (byte)(messageByte[j] ^ BH_5[j]);
        }
    }


    private static void Verify(String pairingParametersFileName, String publicParameterFileName, String pkFileName,String skFileName, String signCryptFileName, String users,String rec,String messages) throws NoSuchAlgorithmException, InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        String PE = pubProp.getProperty("E");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Element E = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PE)).getImmutable();

        Properties pkp = loadPropFromFile(pkFileName);
        Properties sigC = loadPropFromFile(signCryptFileName);
        Properties skp = loadPropFromFile(skFileName);

        //取出发送放的公钥和签名以及TK来验证。

        String PW = sigC.getProperty("W"+users);

        Element W = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PW)).getImmutable();

        String Y = pkp.getProperty("Y"+users);
        Element SY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Y)).getImmutable();

        String T = pkp.getProperty("T"+users);
        Element ST = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T)).getImmutable();


        String Y1 = pkp.getProperty("Y"+rec);
        Element RY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Y1)).getImmutable();

        String T1 = pkp.getProperty("T"+rec);
        Element RT = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T1)).getImmutable();


        byte[] BH_1 = sha1(users+SY.toString());
        Element ks=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        String U1 = sigC.getProperty("U"+users);
        Element U = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(U1)).getImmutable();
        String V1 = sigC.getProperty("V"+users);
        Element V = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(V1)).getImmutable();

        String x = skp.getProperty("x"+rec);
        Element Rx = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x)).getImmutable();

        String t = skp.getProperty("t"+rec);
        Element Rt = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(t)).getImmutable();

        byte[] BH_4 = sha1(messages+U.toString()+V.toString()+rec+RY.toString()+RT.toString()+users+SY.toString()+ST.toString());
        Element H_4=bp.getZr().newElementFromHash(BH_4,0,BH_4.length).getImmutable();



        byte[] BH_3 = sha1(U.toString()+V.toString()+rec+RY.toString()+RT.toString()+users+SY.toString()+ST.toString());
        Element g=bp.getZr().newElementFromHash(BH_3,0,BH_3.length).getImmutable();

        Element option =bp.pairing(U,V).powZn(Rx.add(Rt.mul(g)));

        Element element = SY.add(P_pub.powZn(ks).add(ST.powZn(H_4)));

        Element judge = bp.pairing(W,element);

    }





    private static void signCrypt(String pairingParametersFileName, String publicParameterFileName, String skFileName, String pkFileName, String messages, String users, String signCryptFileName,String rec) throws NoSuchAlgorithmException, InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pubProp = loadPropFromFile(publicParameterFileName);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties pkp = loadPropFromFile(pkFileName);
        Properties skp = loadPropFromFile(skFileName);

        String Y1 = pkp.getProperty("Y"+rec);
        Element RY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Y1)).getImmutable();

        String T1 = pkp.getProperty("T"+rec);
        Element RT = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T1)).getImmutable();

        String Y = pkp.getProperty("Y"+users);
        Element SY = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Y)).getImmutable();

        String T = pkp.getProperty("T"+users);
        Element ST = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T)).getImmutable();


        String x = skp.getProperty("x"+users);
        Element Sx = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(x)).getImmutable();

        String t = skp.getProperty("t"+users);
        Element St = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(t)).getImmutable();


        //发送方的操作
        byte[] BH_1 = sha1(rec+RY.toString());
        Element kd=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        Element u= bp.getZr().newRandomElement().getImmutable();
        Element v= bp.getZr().newRandomElement().getImmutable();
        Element U = P.powZn(u);
        Element V = P.powZn(v);

        byte[] BH_3 = sha1(U.toString()+V.toString()+rec+RY.toString()+RT.toString()+users+SY.toString()+ST.toString());
        Element g=bp.getZr().newElementFromHash(BH_3,0,BH_3.length).getImmutable();

        Element element = RY.add(P_pub.powZn(kd)).add(RT.powZn(g));
        Element option = bp.pairing(P.powZn(u.mul(v)),element);

        byte[] BH_4 = sha1(messages+U.toString()+V.toString()+rec+RY.toString()+RT.toString()+users+SY.toString()+ST.toString());
        Element H_4=bp.getZr().newElementFromHash(BH_4,0,BH_4.length).getImmutable();

        Element W = P.powZn(Sx.add(H_4.mul(St)).invert());

        byte[] BH_5 = sha1(messages+U.toString()+V.toString()+option.toString()+rec+RY.toString()+RT.toString()+users+SY.toString()+ST.toString());
        Element a=bp.getZr().newElementFromHash(BH_5,0,BH_5.length).getImmutable();
        byte[] messageByte = messages.getBytes();
        byte[] ci = new byte[messageByte.length];
        for (int j = 0; j < messageByte.length; j++){
            ci[j] = (byte)(messageByte[j] ^ BH_5[j]);
        }
        Element c = bp.getZr().newElementFromHash(ci,0,ci.length);

        Properties sigC=loadPropFromFile(signCryptFileName);
        sigC.setProperty("a"+users, Base64.getEncoder().encodeToString(a.toBytes()));
        sigC.setProperty("U"+users, Base64.getEncoder().encodeToString(U.toBytes()));
        sigC.setProperty("V"+users, Base64.getEncoder().encodeToString(V.toString().getBytes()));
        sigC.setProperty("W"+users ,Base64.getEncoder().encodeToString(W.toBytes()));

        storePropToFile(sigC,signCryptFileName);




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
        Element y = bp.getZr().newRandomElement().getImmutable();

        Element Y = P.powZn(y).getImmutable();

        byte[] BH_1 = sha1(user+Y.toString());
        Element ks=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        Element x = y.add(ks.mul(s));
        //将公钥存储起来。
        pkp.setProperty("Y"+user,Base64.getEncoder().encodeToString(Y.toBytes()));
        skp.setProperty("x"+user,Base64.getEncoder().encodeToString(x.toBytes()));
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

        Element t = bp.getZr().newRandomElement().getImmutable();
        Element T = P.powZn(t).getImmutable();
        //将公钥存储起来。
        pkp.setProperty("T"+user,Base64.getEncoder().encodeToString(T.toBytes()));
        skp.setProperty("t"+user,Base64.getEncoder().encodeToString(t.toBytes()));

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
