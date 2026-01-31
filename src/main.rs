use clap::Parser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = archer::cli::Cli::parse();

    match cli.command {
        archer::cli::Commands::Enc {
            input,
            output,
            min_size_mb,
        } => {
            let password = archer::cli::get_password(true)?;
            archer::encrypt(
                &input,
                output.as_deref(),
                min_size_mb.unwrap_or(0),
                password.as_str(),
            )?;
        }

        archer::cli::Commands::Dec { input, output } => {
            let password = archer::cli::get_password(false)?;
            archer::decrypt(&input, &output, password.as_str())?;
        }
    }

    Ok(())
}
