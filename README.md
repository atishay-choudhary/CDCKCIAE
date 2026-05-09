
C:\USERS\ATISH\DOCUMENTS\B.TECH CSE (PLAIN)\B.TECH SEM-6\ML\PROJECT - II\CDKCIAE
│   main.py
│   README.md
│   
├───datasets
│   ├───cisa
│   │   └───raw
│   │           known_exploited_vulnerabilities.json
│   │           
│   ├───cves
│   │   └───raw
│   │           nvdcve-2.0-2024.json
│   │           nvdcve-2.0-2025.json
│   │           nvdcve-2.0-modified.json
│   │           nvdcve-2.0-recent.json
│   │           
│   ├───historical
│   │       historical_attacks.json
│   │       
│   └───mitre
│       └───raw
│               enterprise-attack.json
│               
├───engine
│   │   pipeline.py
│   │   __init__.py
│   │   
│   ├───crawlers
│   │   │   base.py
│   │   │   dark_crawler.py
│   │   │   forum_crawler.py
│   │   │   source_list.py
│   │   │   __init__.py
│   │   │   
│   │   └───__pycache__
│   │           base.cpython-312.pyc
│   │           base.cpython-313.pyc
│   │           dark_crawler.cpython-312.pyc
│   │           dark_crawler.cpython-313.pyc
│   │           forum_crawler.cpython-312.pyc
│   │           forum_crawler.cpython-313.pyc
│   │           source_list.cpython-312.pyc
│   │           source_list.cpython-313.pyc
│   │           __init__.cpython-312.pyc
│   │           __init__.cpython-313.pyc
│   │           
│   ├───datasets
│   │   │   dataset_loader.py
│   │   │   __init__.py
│   │   │   
│   │   └───__pycache__
│   │           dataset_loader.cpython-312.pyc
│   │           dataset_loader.cpython-313.pyc
│   │           __init__.cpython-312.pyc
│   │           __init__.cpython-313.pyc
│   │           
│   ├───extractors
│   │   │   regex_basics.py
│   │   │   __init__.py
│   │   │   
│   │   └───__pycache__
│   │           regex_basics.cpython-312.pyc
│   │           regex_basics.cpython-313.pyc
│   │           __init__.cpython-312.pyc
│   │           __init__.cpython-313.pyc
│   │           
│   ├───graph
│   │   │   graph_visualizer.py
│   │   │   threat_graph.py
│   │   │   __init__.py
│   │   │   
│   │   └───__pycache__
│   │           graph_visualizer.cpython-312.pyc
│   │           threat_graph.cpython-312.pyc
│   │           __init__.cpython-312.pyc
│   │           
│   ├───intelligence
│   │   │   intelligence_summary.py
│   │   │   killchain_mapper.py
│   │   │   narrative_generator.py
│   │   │   threat_scorer.py
│   │   │   __init__.py
│   │   │   
│   │   └───__pycache__
│   │           intelligence_summary.cpython-312.pyc
│   │           killchain_mapper.cpython-312.pyc
│   │           killchain_mapper.cpython-313.pyc
│   │           narrative_generator.cpython-312.pyc
│   │           narrative_generator.cpython-313.pyc
│   │           threat_scorer.cpython-312.pyc
│   │           threat_scorer.cpython-313.pyc
│   │           __init__.cpython-312.pyc
│   │           __init__.cpython-313.pyc
│   │           
│   ├───nlp
│   │   │   entity_extractor.py
│   │   │   keyword_analysis.py
│   │   │   preprocess.py
│   │   │   tfidf_analysis.py
│   │   │   __init__.py
│   │   │   
│   │   └───__pycache__
│   │           entity_extractor.cpython-312.pyc
│   │           keyword_analysis.cpython-312.pyc
│   │           keyword_analysis.cpython-313.pyc
│   │           preprocess.cpython-312.pyc
│   │           preprocess.cpython-313.pyc
│   │           tfidf_analysis.cpython-312.pyc
│   │           tfidf_analysis.cpython-313.pyc
│   │           __init__.cpython-312.pyc
│   │           __init__.cpython-313.pyc
│   │           
│   ├───reports
│   │   │   report_generator.py
│   │   │   __init__.py
│   │   │   
│   │   └───__pycache__
│   │           report_generator.cpython-312.pyc
│   │           report_generator.cpython-313.pyc
│   │           __init__.cpython-312.pyc
│   │           __init__.cpython-313.pyc
│   │           
│   └───__pycache__
│           pipeline.cpython-312.pyc
│           pipeline.cpython-313.pyc
│           __init__.cpython-312.pyc
│           __init__.cpython-313.pyc
│           
├───mock_sites
│       forum1.html
│       leak1.html
│       market1.html
│       
└───outputs
        threat_graph.png
        threat_intelligence_report.pdf
        