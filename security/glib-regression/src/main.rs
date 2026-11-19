use glib::prelude::*;
use std::hint::black_box;

fn main() {
    for _ in 0..1000 {
        let values = ["first", "", "中文", "last"];
        let variant = black_box(values.to_variant());
        assert_eq!(
            variant.array_iter_str().unwrap().collect::<Vec<_>>(),
            values
        );
        assert_eq!(
            variant.array_iter_str().unwrap().rev().collect::<Vec<_>>(),
            ["last", "中文", "", "first"]
        );
        let mut mixed = variant.array_iter_str().unwrap();
        assert_eq!(mixed.next(), Some("first"));
        assert_eq!(mixed.next_back(), Some("last"));
        assert_eq!(mixed.nth(1), Some("中文"));
        assert_eq!(mixed.next_back(), None);
        assert_eq!(variant.array_iter_str().unwrap().nth_back(1), Some("中文"));
        assert_eq!(variant.array_iter_str().unwrap().last(), Some("last"));
        assert_eq!(variant.array_iter_str().unwrap().nth(usize::MAX), None);
        let empty = Vec::<String>::new().to_variant();
        assert_eq!(empty.array_iter_str().unwrap().next(), None);
    }
    println!("Optimized VariantStrIter forward/reverse/indexed/Unicode regression passed");
}
