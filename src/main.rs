use num_cpus;
use std::process::exit;
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;
use crypto::mac::Mac;
use structopt::StructOpt;
use scoped_threadpool::Pool;

#[derive(StructOpt, Debug)]
#[structopt(name = "args", about = "arguments")]
struct Opt {
    #[structopt(short = "t", long = "token", help = "the JWT token",
    default_value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.\
                cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE")]
    token: String,

    #[structopt(short = "a", long = "alphabet", help = "the alphabet",
    default_value = "eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789")]
    alphabet: String,

    #[structopt(short = "x", long = "maxlength", help = "Maximum Length", default_value = "6")]
    max_length: usize,
}

fn main() {
    use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};

    let opt = Opt::from_args();
    println!("{:?}", opt);

    let token: &str = &opt.token;

    let parts: Vec<&str> = token.split(".").collect();
    println!("{:?}", parts);

    // Decode the signature
    let presented_header: Vec<u8> =
        parts[0].from_base64().expect("JWT header Base64 decoding failed");
    let presented_payload: Vec<u8> =
        parts[1].from_base64().expect("JWT payload Base64 decoding failed");
    let presented_signature: Vec<u8> =
        parts[2].from_base64().expect("JWT signature Base64 decoding failed");

    let mut message_to_encrypt = String::new();
    message_to_encrypt.push_str(&presented_header.clone().to_base64(STANDARD));
    message_to_encrypt.push('.');
    message_to_encrypt.push_str(&presented_payload.clone().to_base64(STANDARD));

    println!();
    println!("Presented Header: {}",
             String::from_utf8_lossy(presented_header.as_slice()));
    println!("Presented Payload: {}",
             String::from_utf8_lossy(presented_payload.as_slice()));
    println!("Presented Signature (len) {}: {}",
             presented_signature.len(),
             String::from_utf8_lossy(presented_signature.as_slice()));
    println!();

   get_words(&opt.alphabet, opt.max_length, &presented_signature, &message_to_encrypt);
}


fn get_words(alphabet_str: &str, max_length: usize, presented_signature: &Vec<u8>, data_to_sign: &str) {
    let presented_signature = presented_signature.as_slice();
    let alphabet = alphabet_str.as_bytes();
    let data_to_sign = data_to_sign.as_bytes();
    let alphabet_str = alphabet_str.as_bytes();

    // index[0] is words with length 1. index[1] is words with length 2. index[2] is words with length 3.
    let mut index: Vec<Vec<u8>> = Vec::new();

    for letter in alphabet_str {
        index.push(vec![*letter]);
    }

    let mut pool = Pool::new(num_cpus::get() as u32);
    let sha256 = Sha256::new();

    pool.scoped(|scoped| {
        for length in 1..max_length {
            println!("Checking secrets of length {}", length);
            let mut new_words: Vec<Vec<u8>> = Vec::new();

            while let Some(existing_word) = index.pop() {
                for character in alphabet {
                    let mut secret = existing_word.clone();
                    secret.push(*character);
                    new_words.push(secret.clone());
                    // let secret = secret.as_bytes();
                    scoped.execute(move || {
                        let mut hmac = Hmac::new(sha256, &secret);
                        hmac.input(data_to_sign);

                        if &presented_signature == &hmac.result().code() {
                            // println!("Found! Created signature    : {} using the secret: {}", String::from_utf8_lossy(raw.as_slice()), secret);
                            println!("Found using the secret: {}", String::from_utf8_lossy(&secret.to_vec()));
                            exit(0);
                        }
                    });
                };
            }

            index = new_words;
        }
    });
}


#[cfg(test)]
mod test {
    use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};
    use super::get_words;

    #[test]
    fn check_works() {
        let parts: Vec<&str> = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                                eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.\
                                cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE".split(".").collect();
        println!("{:?}", parts);

        // Decode the signature
        let presented_header: Vec<u8> =
            parts[0].from_base64().expect("JWT header Base64 decoding failed");
        let presented_payload: Vec<u8> =
            parts[1].from_base64().expect("JWT payload Base64 decoding failed");
        let presented_signature: Vec<u8> =
            parts[2].from_base64().expect("JWT signature Base64 decoding failed");

        let mut message_to_encrypt = String::new();
        message_to_encrypt.push_str(&presented_header.clone().to_base64(STANDARD));
        message_to_encrypt.push('.');
        message_to_encrypt.push_str(&presented_payload.clone().to_base64(STANDARD));

        let alphabet = "Sn1f";

        get_words(&alphabet, 4, &presented_signature, &message_to_encrypt);
    }
}
