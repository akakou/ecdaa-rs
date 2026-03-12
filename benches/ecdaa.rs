use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ecdaa::{
    cred::Credential,
    issuer::{IPK, ISK},
    join::ReqForJoin,
    signature::Signature,
    fp256bn_amcl::rand::RAND,
};

#[derive(Copy, Clone)]
struct BenchContext {
    isk: ISK,
    ipk: IPK,
    req: ReqForJoin,
    sk: ecdaa::fp256bn_amcl::fp256bn::big::BIG,
    cred: Credential,
    signature: Signature,
}

fn seeded_rng() -> RAND {
    let mut raw = [0_u8; 100];
    let mut rng = RAND::new();

    rng.clean();
    for (i, b) in raw.iter_mut().enumerate() {
        *b = i as u8;
    }
    rng.seed(100, &raw);

    rng
}

fn setup_context(message: &[u8], basename: &[u8]) -> BenchContext {
    let mut rng = seeded_rng();

    let isk = ISK::random(&mut rng);
    let ipk = IPK::random(&isk, &mut rng);
    let (req, sk) = ReqForJoin::random(message, &mut rng).expect("join request");
    let cred = Credential::with_no_encryption(&req, message, &isk).expect("credential");
    let signature =
        Signature::sign(message, basename, &sk, &cred, true, &mut rng).expect("signature");

    BenchContext {
        isk,
        ipk,
        req,
        sk,
        cred,
        signature,
    }
}

fn ecdaa_benches(c: &mut Criterion) {
    let message = vec![0_u8, 2, 3];
    let basename = vec![0_u8, 2, 3, 4];
    let ctx = setup_context(&message, &basename);

    let mut group = c.benchmark_group("ecdaa");

    group.bench_function("join_request_random", |b| {
        b.iter_batched(
            seeded_rng,
            |mut rng| {
                black_box(ReqForJoin::random(black_box(&message), &mut rng).expect("join request"))
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("join_request_valid", |b| {
        b.iter(|| black_box(ctx.req.valid(black_box(&message)).expect("valid request")))
    });

    group.bench_function("credential_issue_no_encryption", |b| {
        b.iter(|| {
            black_box(
                Credential::with_no_encryption(black_box(&ctx.req), black_box(&message), &ctx.isk)
                    .expect("credential"),
            )
        })
    });

    group.bench_function("credential_valid", |b| {
        b.iter(|| black_box(ctx.cred.valid(black_box(&ctx.ipk)).expect("valid credential")))
    });

    group.bench_function("signature_sign", |b| {
        b.iter_batched(
            seeded_rng,
            |mut rng| {
                black_box(
                    Signature::sign(
                        black_box(&message),
                        black_box(&basename),
                        &ctx.sk,
                        &ctx.cred,
                        true,
                        &mut rng,
                    )
                    .expect("signature"),
                )
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("signature_verify", |b| {
        b.iter(|| {
            black_box(
                ctx.signature
                    .verify(black_box(&message), black_box(&basename), &ctx.ipk, true)
                    .expect("verify signature"),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, ecdaa_benches);
criterion_main!(benches);
