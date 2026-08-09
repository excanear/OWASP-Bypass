"""Prints a category-grouped solved/failed table."""


def print_report(results: list[dict]) -> None:
    by_category: dict[str, list[dict]] = {}
    for r in results:
        by_category.setdefault(r["category"], []).append(r)

    total_solved = sum(1 for r in results if r["solved"])
    for category, items in sorted(by_category.items()):
        solved_count = sum(1 for i in items if i["solved"])
        print(f"\n{category} ({solved_count}/{len(items)})")
        for item in items:
            mark = "OK  " if item["solved"] else "FAIL"
            extra = f" - {item['error']}" if item["error"] else ""
            print(f"  [{mark}] {item['key']} ({item['duration']}s){extra}")

    print(f"\nTOTAL: {total_solved}/{len(results)} solved")
