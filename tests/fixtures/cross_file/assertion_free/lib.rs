pub fn parse(input: &str) -> usize {
    input.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(input: &str, expected: usize) {
        assert_eq!(parse(input), expected);
    }

    #[test]
    fn delegates_to_a_helper() {
        check("abc", 3);
    }

    #[test]
    fn checks_nothing() {
        parse("abc");
    }

    #[test]
    fn delegates_to_external_test_support() {
        support::run_scenario("parse");
    }

    #[test]
    fn compiles_only() {
        let _: fn(&str) -> usize = parse;
    }
}
