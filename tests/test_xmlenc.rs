use xmlsec::{XmlSecKey, XmlSecKeyFormat, XmlSecEncryptionContext};
use libxml::parser::Parser as XmlParser;

#[test]
fn test_decrypt_document() {
    let mut ctx = XmlSecEncryptionContext::new();

    let key = XmlSecKey::from_des_file("tests/resources/deskey.bin")
        .expect("Failed to load encryption key");
    ctx.register_key(key);

    let parser = XmlParser::default();
    let enc_doc = parser.parse_file("tests/resources/encrypt2-res.xml")
        .expect("Unable to load encrypted XML");

    let root = enc_doc.get_root_element().expect("no root");
    ctx.decrypt_node(&root).expect("decryption failed");


    let env = enc_doc.get_root_element().unwrap();
    let data = env.get_first_element_child().unwrap();
    assert_eq!(data.get_name(), "Data");
    assert_eq!(data.get_content().trim(), "Hello, World!");
}

#[test]
fn test_decrypt_aes128() {
    let mut ctx = XmlSecEncryptionContext::new();

    let key = XmlSecKey::from_aes_file("tests/resources/aes128.key")
        .expect("Failed to load AES key");
    ctx.insert_key(key);

    let parser = XmlParser::default();
    let enc_doc = parser.parse_file("tests/resources/encrypt_aes128_res.xml")
        .expect("Unable to load encrypted XML");

    let root = enc_doc.get_root_element().expect("no root");
    ctx.decrypt_node(&root).expect("decryption failed");

    let env = enc_doc.get_root_element().unwrap();
    let data = env.get_first_element_child().unwrap();
    assert_eq!(data.get_name(), "Data");
    assert_eq!(data.get_content().trim(), "Hello, World!");
}

#[test]
fn test_decrypt_aes256_rsa_oaep() {
    let mut ctx = XmlSecEncryptionContext::new();

    let mut key = XmlSecKey::from_file("tests/resources/key.pem", XmlSecKeyFormat::Pem, None)
        .expect("Failed to load RSA key");
    key.set_name("key.pem");
    ctx.register_key(key);

    let parser = XmlParser::default();
    let enc_doc = parser.parse_file("tests/resources/encrypt_aes256_rsa_oaep_res.xml")
        .expect("Unable to load encrypted XML");

    let root = enc_doc.get_root_element().expect("no root");
    ctx.decrypt_node(&root).expect("decryption failed");

    let env = enc_doc.get_root_element().unwrap();
    let data = env.get_first_element_child().unwrap();
    assert_eq!(data.get_name(), "Data");
    assert_eq!(data.get_content().trim(), "Hello, World!");
}
