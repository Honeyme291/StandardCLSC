package Zhou;

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

public class Zhou {
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
        String dir = "E:/java program/standard/database/Zhou/";
        String pairingParametersFileName = "E:/java program/standard/database/Zhou/a.properties";
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
            UnSignCryption(pairingParametersFileName,publicParameterFileName,pkFileName,skFileName,signCryptFileName,users[i],rec,messages[i]);
            long end = System.currentTimeMillis();
            System.out.print("运行时间为");
            System.out.println(end - start);

        }
    }

    private static void Verify(String pairingParametersFileName, String publicParameterFileName, String pkFileName, String skFileName, String signCryptFileName, String user, String rec, String message) throws InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("g");
        String P_pubistr=publicParams.getProperty("g1");
        String h1m=publicParams.getProperty("h1");
        Element g=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element g1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Element h1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(h1m.getBytes())).getImmutable();

        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);

        String UPK1m = pkp.getProperty("UPK1"+user);

        Element UPKS1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UPK1m.getBytes())).getImmutable();

        String UPK1RR = pkp.getProperty("UPK1"+rec);

        Element UPKR1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UPK1RR.getBytes())).getImmutable();



        String SK1m = skp.getProperty("SK1"+user);

        Element SK1S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SK1m.getBytes())).getImmutable();

        String SK2m = skp.getProperty("SK2"+user);

        Element SK2S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SK2m.getBytes())).getImmutable();
        String SK3m = skp.getProperty("SK3"+user);

        Element SK3S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SK3m.getBytes())).getImmutable();
        Properties sigC=loadPropFromFile(signCryptFileName);
        String sign1m = sigC.getProperty("sign1"+user);

        Element sign1 = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(sign1m.getBytes())).getImmutable();
        String sign2m = sigC.getProperty("sign2"+user);

        Element sign2 = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(sign2m.getBytes())).getImmutable();

        String sign3m = sigC.getProperty("sign3"+user);

        Element sign3 = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(sign3m.getBytes())).getImmutable();

        String sign4m = sigC.getProperty("sign4"+user);

        Element sign4 = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(sign4m.getBytes())).getImmutable();
        String sign5m = sigC.getProperty("sign5"+user);

        Element sign5 = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(sign5m.getBytes())).getImmutable();

    }

    private static void UnSignCryption(String pairingParametersFileName, String publicParameterFileName, String pkFileName, String skFileName, String signCryptFileName, String user, String rec, String message) throws InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("g");
        String P_pubistr=publicParams.getProperty("g1");
        String h1m=publicParams.getProperty("h1");
        Element g=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element g1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Element h1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(h1m.getBytes())).getImmutable();

        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);

        String UPK1m = pkp.getProperty("UPK1"+user);

        Element UPKS1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UPK1m.getBytes())).getImmutable();

        String UPK1RR = pkp.getProperty("UPK1"+rec);

        Element UPKR1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UPK1RR.getBytes())).getImmutable();



        String SK1m = skp.getProperty("SK1"+user);

        Element SK1S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SK1m.getBytes())).getImmutable();

        String SK2m = skp.getProperty("SK2"+user);

        Element SK2S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SK2m.getBytes())).getImmutable();
        String SK3m = skp.getProperty("SK3"+user);

        Element SK3S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SK3m.getBytes())).getImmutable();
        Properties sigC=loadPropFromFile(signCryptFileName);
        String sign1m = sigC.getProperty("sign1"+user);

        Element sign1 = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(sign1m.getBytes())).getImmutable();
        String sign2m = sigC.getProperty("sign2"+user);

        Element sign2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sign2m.getBytes())).getImmutable();

        String sign3m = sigC.getProperty("sign3"+user);

        Element sign3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sign3m.getBytes())).getImmutable();

        String sign4m = sigC.getProperty("sign4"+user);

        Element sign4 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sign4m.getBytes())).getImmutable();
        String sign5m = sigC.getProperty("sign5"+user);

        Element sign5 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sign5m.getBytes())).getImmutable();

        Element option  = bp.pairing(sign2,SK1S).mul(sign1);

        Element option1 = sign4.mul(SK2S).mul(sign3.mul(SK3S));




    }

    private static void signCrypt(String pairingParametersFileName, String publicParameterFileName, String skFileName, String pkFileName, String message, String user, String signCryptFileName, String rec) throws InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("g");
        String P_pubistr=publicParams.getProperty("g1");
        String h1m=publicParams.getProperty("h1");
        Element g=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element g1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Element h1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(h1m.getBytes())).getImmutable();

        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);

        String UPK1m = pkp.getProperty("UPK1"+user);

        Element UPKS1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UPK1m.getBytes())).getImmutable();

        String UPK1RR = pkp.getProperty("UPK1"+rec);

        Element UPKR1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UPK1RR.getBytes())).getImmutable();



        String SK1m = skp.getProperty("SK1"+user);

        Element SK1S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SK1m.getBytes())).getImmutable();

        String SK2m = skp.getProperty("SK2"+user);

        Element SK2S = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SK2m.getBytes())).getImmutable();

        

        Element t1 = bp.getZr().newRandomElement().getImmutable();
        Element t2 = bp.getZr().newRandomElement().getImmutable();

        Element sign1 = bp.pairing(UPKR1,UPKR1).powZn(t1.invert()).mul(bp.pairing(g,h1));
        Element sign2 = g1.powZn(t2).mul(g.powZn(t2));

        Element sign3 = bp.pairing(g,g).powZn(t1);

        Element sign4 = bp.pairing(g,g).powZn(t2);

        Element sign5 = SK2S;
        Properties sigC=loadPropFromFile(signCryptFileName);
        sigC.setProperty("sign3"+user, Base64.getEncoder().encodeToString(sign3.toBytes()));
        sigC.setProperty("sign1"+user, Base64.getEncoder().encodeToString(sign1.toBytes()));
        sigC.setProperty("sign2"+user, Base64.getEncoder().encodeToString(sign2.toString().getBytes()));
        sigC.setProperty("sign4"+user, Base64.getEncoder().encodeToString(sign4.toBytes()));
        sigC.setProperty("sign5"+user, Base64.getEncoder().encodeToString(sign5.toString().getBytes()));

        storePropToFile(sigC,signCryptFileName);


    }

    private static void KeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("g");
        String P_pubistr=publicParams.getProperty("g1");
        Element g=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element g1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Element x = bp.getZr().newRandomElement().getImmutable();

        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);

        Element UPK1 =  g.powZn(x);

        Element UPK2 = (g1.mul(g)).powZn(x);

        Element SK3 = x;

        skp.setProperty("SK3"+user,Base64.getEncoder().encodeToString(SK3.toBytes()));
        pkp.setProperty("UPK1"+user,Base64.getEncoder().encodeToString(UPK1.toBytes()));
        pkp.setProperty("UPK2"+user,Base64.getEncoder().encodeToString(UPK2.toBytes()));
        storePropToFile(skp,skFileName);
        storePropToFile(pkp,pkFileName);


    }

    private static void PartialKeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("g");
        String P_pubistr=publicParams.getProperty("g1");
        Element g=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element g1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties mskPro = loadPropFromFile(mskFileName);
        String s_istr=mskPro.getProperty("s");
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();
        Properties skp=loadPropFromFile(skFileName);

        Element r = bp.getZr().newRandomElement().getImmutable();

        Element SK1 =g.powZn(r).powZn(s.invert());

        Element SK2 = r;

        skp.setProperty("SK1"+user,Base64.getEncoder().encodeToString(SK1.toBytes()));
        skp.setProperty("SK2"+user,Base64.getEncoder().encodeToString(SK2.toBytes()));
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
        Element g = bp.getG1().newRandomElement().getImmutable();
        Element h1 = bp.getG1().newRandomElement().getImmutable();
        Element g1 = g.powZn(s).getImmutable();
        Element E = bp.pairing(g,g);
        Properties pubProp = new Properties();
        pubProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        pubProp.setProperty("h1", Base64.getEncoder().encodeToString(h1.toBytes()));
        pubProp.setProperty("g1", Base64.getEncoder().encodeToString(g1.toBytes()));
        pubProp.setProperty("E", Base64.getEncoder().encodeToString(E.toBytes()));

        storePropToFile(pubProp, publicParameterFileName);
    }

}
