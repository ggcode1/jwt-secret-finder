use num_cpus;
use std::process::exit;
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;
use crypto::mac::Mac;
use threadpool::ThreadPool;
use structopt::StructOpt;

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


fn get_words(alphabet_str: &str, max_length: usize, presented_signature: &Vec<u8>, data_to_sign: &str) -> Vec<Vec<String>> {

    let alphabet = alphabet_str.as_bytes();

    let mut index: Vec<Vec<String>> = Vec::new(); // index[0] is words with length 1. index[1] is words with length 2. index[2] is words with length 3.
    // index.resize(max_length, vec![]);

    // push the first vector, the vector of single-character alphabet strings
    let mut first_index: Vec<String> = Vec::new();

    for _ in alphabet_str.chars() {
        first_index.push("".to_string());
    }
    // println!("{:?}", first_index);
    index.push(first_index);
    // println!("{:?}", index);

    let pool = ThreadPool::new(num_cpus::get());

    for length in 1..max_length {
        println!("Checking secrets of length {}", length);
        let mut current_index: Vec<String> = Vec::new();

        for existing_word in &index[length - 1] {
            // println!("{:?}", existing_word);

            for i in alphabet {
                let mut secret = existing_word.clone();
                secret.push(*i as char);

                current_index.push(secret.clone());

                let data_to_sign = data_to_sign.to_string();
                let presented_signature = presented_signature.clone();

                pool.execute(move || {
                    let mut hmac = Hmac::new(Sha256::new(), secret.as_bytes());
                    hmac.input(data_to_sign.as_bytes());
                    let mut raw = Vec::with_capacity(32);
                    raw.resize(32, 0); // sha256 produces 256bits, or 32 bytes.
                    hmac.raw_result(raw.as_mut_slice());

                    // println!("Checking {}", String::from_utf8_lossy(raw.as_slice()));
                    // println!("DBG Raw {:?}", raw);
                    // println!("DBG Pre {:?}", String::from_utf8_lossy(presented_signature));
                    // println!("DBG Secret is: {}", secret);

                    if presented_signature == raw {
                        println!("Found! Created signature    : {} using the secret: {}", String::from_utf8_lossy(raw.as_slice()), secret);
                        exit(0);
                    }
                });
            }
        }

        index.push(current_index);
    }
    index
}


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
