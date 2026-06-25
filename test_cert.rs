use openssl::x509::{X509, X509NameBuilder};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::x509::extension::SubjectAlternativeName;

fn extract_identity(cert: &X509) -> Option<String> {
    if let Some(sans) = cert.subject_alt_names() {
        for san in sans {
            if let Some(uri) = san.uri() {
                return Some(uri.to_string());
            }
            if let Some(dns) = san.dnsname() {
                return Some(dns.to_string());
            }
        }
    }
    for entry in cert.subject_name().entries() {
        if entry.object().nid() == openssl::nid::Nid::COMMONNAME {
            if let Ok(cn) = entry.data().as_utf8() {
                return Some(cn.to_string());
            }
        }
    }
    None
}

fn main() {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "spiffe://example.org/agent-1").unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();
    
    println!("Extracted: {:?}", extract_identity(&cert));
}
