CDKCIAE/
│
├── main.py
│
├── engine/
│   │
│   ├── pipeline.py
│   │
│   ├── crawlers/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── dark_crawler.py
│   │   ├── forum_crawler.py
│   │   └── source_list.py
│   │
│   ├── extractor/
│   │   ├── __init__.py
│   │   └── regex_basic.py
│   │
│   ├── intelligence/
│   │   ├── __init__.py
│   │   ├── killchain_mapper.py
│   │   └── threat_scorer.py
│   │
│   └── reports/
│       ├── __init__.py
│       └── report_generator.py
│
└── mock_sites/
    ├── forum1.html
    ├── market1.html
    └── leak1.html