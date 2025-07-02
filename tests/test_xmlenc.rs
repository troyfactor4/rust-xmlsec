use xmlsec::{XmlSecKey, XmlSecKeyFormat, XmlSecEncryptionContext};
use libxml::parser::Parser as XmlParser;


#[test]
fn test_encrypt_decrypt_aes128() {
    let mut ctx = XmlSecEncryptionContext::new();

    let key = XmlSecKey::from_aes_file("tests/resources/aes128.key")
        .expect("Failed to load AES key");
    ctx.insert_key(key);

    let parser = XmlParser::default();

    let mut doc = parser.parse_file("tests/resources/encrypt2-doc.xml")
        .expect("Unable to load XML to encrypt");
    let tmpl_doc = parser.parse_file("tests/resources/encrypt_aes128_tmpl.xml")
        .expect("Unable to load encryption template");

    let data = doc.get_root_element().unwrap().get_first_element_child().unwrap();
    let mut tmpl = tmpl_doc.get_root_element().unwrap();
    tmpl.unlink();
    let tmpl = doc.import_node(&mut tmpl).expect("import failed");

    ctx.encrypt_node(&tmpl, &data).expect("encryption failed");

    let mut dec_ctx = XmlSecEncryptionContext::new();
    let key = XmlSecKey::from_aes_file("tests/resources/aes128.key")
        .expect("Failed to load AES key");
    dec_ctx.insert_key(key);
    dec_ctx.decrypt_node(&tmpl).expect("decryption failed");

    let env = doc.get_root_element().unwrap();
    let data = env.get_first_element_child().unwrap();
    assert_eq!(data.get_name(), "Data");
    assert_eq!(data.get_content().trim(), "Hello, World!");
}

#[test]
fn test_encrypt_decrypt_aes256_rsa_oaep() {
    let mut ctx = XmlSecEncryptionContext::new();

    let aes_key = XmlSecKey::from_aes_file("tests/resources/aes256.key")
        .expect("Failed to load AES key");
    ctx.insert_key(aes_key);

    let mut rsa_key = XmlSecKey::from_file("tests/resources/key.pem", XmlSecKeyFormat::Pem, None)
        .expect("Failed to load RSA key");
    rsa_key.set_name("key.pem");
    ctx.register_key(rsa_key);

    let parser = XmlParser::default();

    let mut doc = parser.parse_file("tests/resources/encrypt2-doc.xml")
        .expect("Unable to load XML to encrypt");
    let tmpl_doc = parser.parse_file("tests/resources/encrypt_aes256_rsa_oaep_tmpl.xml")
        .expect("Unable to load encryption template");

    let data = doc.get_root_element().unwrap().get_first_element_child().unwrap();
    let mut tmpl = tmpl_doc.get_root_element().unwrap();
    tmpl.unlink();
    let tmpl = doc.import_node(&mut tmpl).expect("import failed");

    ctx.encrypt_node(&tmpl, &data).expect("encryption failed");

    let mut dec_ctx = XmlSecEncryptionContext::new();
    let aes_key = XmlSecKey::from_aes_file("tests/resources/aes256.key")
        .expect("Failed to load AES key");
    dec_ctx.insert_key(aes_key);
    let mut rsa_key = XmlSecKey::from_file("tests/resources/key.pem", XmlSecKeyFormat::Pem, None)
        .expect("Failed to load RSA key");
    rsa_key.set_name("key.pem");
    dec_ctx.register_key(rsa_key);
    dec_ctx.decrypt_node(&tmpl).expect("decryption failed");

    let env = doc.get_root_element().unwrap();
    let data = env.get_first_element_child().unwrap();
    assert_eq!(data.get_name(), "Data");
    assert_eq!(data.get_content().trim(), "Hello, World!");
}
