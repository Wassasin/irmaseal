use clap::ArgMatches;
use futures::SinkExt;
use irmaseal_core::stream::Sealer;
use irmaseal_core::Identity;
use std::io::Read;
use std::time::SystemTime;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub async fn exec(m: &ArgMatches<'_>) {
    let mut rng = rand::thread_rng();

    let input = m.value_of("INPUT").unwrap();
    let email = m.value_of("email");
    let bsn = m.value_of("bsn");
    let server = m.value_of("server").unwrap();
    let timestamp = now();

    let i = match (email, bsn) {
        (Some(email), None) => {
            Identity::new(timestamp, "pbdf.pbdf.email.email", Some(email)).unwrap()
        }
        (None, Some(bsn)) => {
            Identity::new(timestamp, "pbdf.gemeente.personalData.bsn", Some(bsn)).unwrap()
        }
        _ => {
            eprintln!("Expected either email or BSN");
            return;
        }
    };

    let client = crate::client::Client::new(server).unwrap();

    let parameters = client.parameters().await.unwrap();
    eprintln!("Fetched parameters from {}", server);
    eprintln!("Encrypting for recipient {:#?}", i);

    let output = format!("{}.irma", input);
    let mut w = crate::util::FileWriter::new(std::fs::File::create(&output).unwrap());

    let mut sealer = Sealer::new(&i, &parameters.public_key, &mut rng)
        .await
        .unwrap();
    let src = std::fs::File::open(input).unwrap();

    eprintln!("Encrypting {}...", input);

    let input_iter = src.bytes().map(|next| next.unwrap());
    let input_stream = futures::stream::iter(input_iter);
    sealer.seal(input_stream, &mut w).await.unwrap();
    // TODO: Is it logical to let the caller close the sink (as it also initialized it) or can irmaseal-core better do so?
    w.close().await.unwrap();

    eprintln!("Result written to {}", output);
}
