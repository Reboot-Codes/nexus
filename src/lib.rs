#![feature(stmt_expr_attributes)]
#![feature(let_chains)]

pub mod arbiter;
pub mod client;
pub mod server;
pub mod user;
pub mod utils;

pub fn add(left: u64, right: u64) -> u64 {
  left + right
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_works() {
    let result = add(2, 2);
    assert_eq!(result, 4);
  }
}
