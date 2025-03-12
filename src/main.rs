use nexus::add;

fn main() {
  // TODO: Wrap embedable server in this binary so it can be used outside of any modules that use this library.
  println!("Hallo welt! 2 + 2 = {}", add(2, 2));
}
