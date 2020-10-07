use crate::stream::*;
use crate::*;

use futures::executor::block_on;
use futures::io::Cursor;
use rand::RngCore;

struct DefaultProps {
    pub i: Identity,
    pub pk: ibe::kiltz_vahlis_one::PublicKey,
    pub sk: ibe::kiltz_vahlis_one::SecretKey,
}

impl Default for DefaultProps {
    fn default() -> DefaultProps {
        let mut rng = rand::thread_rng();
        let i = Identity::new(
            1566722350,
            "pbdf.pbdf.email.email",
            Some("w.geraedts@sarif.nl"),
        )
        .unwrap();

        let (pk, sk) = ibe::kiltz_vahlis_one::setup(&mut rng);

        DefaultProps { i, pk, sk }
    }
}

fn seal<'a>(props: &DefaultProps, content: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, pk, sk: _ } = props;

    let mut buf: Vec<u8> = Vec::new();

    let future = async {
        let mut s = Sealer::new(&i, &PublicKey(pk.clone()), &mut rng).unwrap();
        s.seal(content, &mut buf).await.unwrap();
    };
    block_on(future);

    buf
}

fn unseal(props: &DefaultProps, buf: &[u8]) -> (Vec<u8>, bool) {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, pk, sk } = props;

    let future = async {
        let mut cursor = Cursor::new(buf);
        let (i2, o) = OpenerSealed::new(&mut cursor).await.unwrap();

        assert_eq!(i, &i2);

        let usk = ibe::kiltz_vahlis_one::extract_usk(&pk, &sk, &i2.derive(), &mut rng);
        let mut dst = Vec::new();
        let validated = o.unseal(&UserSecretKey(usk), &mut dst).await.unwrap();

        (dst, validated)
    };
    block_on(future)
}

fn seal_and_unseal(props: &DefaultProps, content: &[u8]) -> (Vec<u8>, bool) {
    let buf = seal(props, content);
    unseal(props, &buf)
}

fn do_test(props: &DefaultProps, content: &mut [u8]) {
    rand::thread_rng().fill_bytes(content);
    let (dst, valid) = seal_and_unseal(props, content);

    assert_eq!(&content.as_ref(), &dst.as_slice());
    assert!(valid);
}

#[test]
fn reflection_sealer_opener() {
    let props = DefaultProps::default();

    do_test(&props, &mut [0u8; 0]);
    do_test(&props, &mut [0u8; 1]);
    do_test(&props, &mut [0u8; 511]);
    do_test(&props, &mut [0u8; 512]);
    do_test(&props, &mut [0u8; 1008]);
    do_test(&props, &mut [0u8; 1023]);
    do_test(&props, &mut [0u8; 60000]);
}

#[test]
fn corrupt_body() {
    let props = DefaultProps::default();

    let mut content = [0u8; 60000];
    rand::thread_rng().fill_bytes(&mut content);

    let mut buf = seal(&props, &content);
    buf[1000] += 0x02;
    let (dst, valid) = unseal(&props, &buf);

    assert_ne!(&content.as_ref(), &dst.as_slice());
    assert!(!valid);
}

#[test]
fn corrupt_hmac() {
    let props = DefaultProps::default();

    let mut content = [0u8; 60000];
    rand::thread_rng().fill_bytes(&mut content);

    let mut buf = seal(&props, &content);
    let mutation_point = buf.len() - 5;
    buf[mutation_point] += 0x02;
    let (dst, valid) = unseal(&props, &buf);

    assert_eq!(&content.as_ref(), &dst.as_slice());
    assert!(!valid);
}
