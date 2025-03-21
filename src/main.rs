use frieda::api::{commit, generate_proof, sample};
use std::fmt::Write;
use std::time::Instant;

fn main() -> frieda::Result<()> {
    println!("🧪 FRIEDA: FRI-based Data Availability Sampling Demo");
    println!("=====================================================\n");

    // Step 1: Generate some test data (In a real scenario, this would be blockchain data)
    println!("⚙️  Generating test data...");
    let data_size = 1024 * 32; // 32 KB
    let data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();
    println!("   Generated {} bytes of test data", data.len());

    // Step 2: Commit to the data
    println!("\n⚙️  Committing data using FRI...");
    let timer = Instant::now();
    let commitment = commit(&data);
    let commit_time = timer.elapsed();
    println!("   Commitment created in {:?}", commit_time);
    println!("   Commitment root: {:?}", hex_encode(&commitment));

    // Step 3: Light client wants to verify data availability
    println!("\n⚙️  Light client initiating data availability sampling...");
    let timer = Instant::now();
    let sample_result = sample(&commitment)?;
    let sample_time = timer.elapsed();
    println!(
        "   Generated {} sample queries in {:?}",
        sample_result.indices.len(),
        sample_time
    );

    // Step 4: In a real scenario, the light client would request the data provider
    // to fulfill these sample queries
    println!("\n⚙️  Simulating data provider responding to sample queries...");
    // In a real implementation, the data provider would use the original data
    // to generate the proofs for the requested indices

    // Step 5: The data provider would normally generate proofs for the requested samples
    println!("\n⚙️  Generating FRI proof for verification...");
    println!("   Note: In this demo, we're using a placeholder proof");
    println!("         In a production system, a complete FRI proof would be generated");

    // This would generate a real proof in a full implementation
    // For this demo, we'll just show the placeholder message
    let _proof_result = generate_proof(&data);
    println!("   Proof would include Merkle paths and consistency proofs for each query");

    // Step 6: A more robust demo would verify the proof
    println!("\n⚙️  In a full implementation, the light client would verify:");
    println!("   - Merkle proofs for each sample");
    println!("   - FRI consistency checks");
    println!("   - Reed-Solomon codeword properties");

    println!("\n🎉 Demo completed successfully!");
    println!("In a real-world deployment, FRIEDA enables:");
    println!(" - Data proven available without downloading it entirely");
    println!(" - Light clients can verify with statistical guarantees");
    println!(" - Polylogarithmic proving overhead");
    println!(" - No trusted setup required");

    Ok(())
}

// Helper function to convert bytes to hex for display
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
