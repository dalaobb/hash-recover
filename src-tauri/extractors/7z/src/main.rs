use extractor_core::run_extractor;
use sevenz_extractor::SevenZExtractor;

fn main() -> ! {
    std::process::exit(run_extractor(&SevenZExtractor) as i32);
}
