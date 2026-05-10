STABLE VERSION STRUCTURE
C:\USERS\ATISH\DOCUMENTS\B.TECH CSE (PLAIN)\B.TECH SEM-6\ML\PROJECT - II\CDKCIAE
│ .gitignore
│ main.py
│ README.md
│  
├───datasets
│ ├───cisa
│ │ └───raw
│ │ known_exploited_vulnerabilities.json
│ │  
│ ├───cves
│ │ └───raw
│ │ nvdcve-2.0-2024.json
│ │ nvdcve-2.0-2025.json
│ │ nvdcve-2.0-modified.json
│ │ nvdcve-2.0-recent.json
│ │  
│ ├───historical
│ │ historical_attacks.json
│ │  
│ └───mitre
│ └───raw
│ enterprise-attack.json
│  
├───engine
│ │ pipeline.py
│ │ **init**.py
│ │  
│ ├───crawlers
│ │ │ base.py
│ │ │ dark_crawler.py
│ │ │ forum_crawler.py
│ │ │ source_list.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ base.cpython-312.pyc
│ │ base.cpython-313.pyc
│ │ dark_crawler.cpython-312.pyc
│ │ dark_crawler.cpython-313.pyc
│ │ forum_crawler.cpython-312.pyc
│ │ forum_crawler.cpython-313.pyc
│ │ source_list.cpython-312.pyc
│ │ source_list.cpython-313.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ ├───datasets
│ │ │ dataset_loader.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ dataset_loader.cpython-312.pyc
│ │ dataset_loader.cpython-313.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ ├───extractors
│ │ │ regex_basics.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ regex_basics.cpython-312.pyc
│ │ regex_basics.cpython-313.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ ├───graph
│ │ │ graph_visualizer.py
│ │ │ threat_graph.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ graph_visualizer.cpython-312.pyc
│ │ threat_graph.cpython-312.pyc
│ │ **init**.cpython-312.pyc
│ │  
│ ├───intelligence
│ │ │ asset_mapper.py
│ │ │ consequence_engine.py
│ │ │ impact_engine.py
│ │ │ intelligence_summary.py
│ │ │ ioc_enrichment.py
│ │ │ killchain_mapper.py
│ │ │ narrative_generator.py
│ │ │ propagation_engine.py
│ │ │ threat_scorer.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ asset_mapper.cpython-312.pyc
│ │ consequence_engine.cpython-312.pyc
│ │ impact_engine.cpython-312.pyc
│ │ intelligence_summary.cpython-312.pyc
│ │ ioc_enrichment.cpython-312.pyc
│ │ killchain_mapper.cpython-312.pyc
│ │ killchain_mapper.cpython-313.pyc
│ │ narrative_generator.cpython-312.pyc
│ │ narrative_generator.cpython-313.pyc
│ │ propagation_engine.cpython-312.pyc
│ │ threat_scorer.cpython-312.pyc
│ │ threat_scorer.cpython-313.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ ├───nlp
│ │ │ entity_extractor.py
│ │ │ keyword_analysis.py
│ │ │ preprocess.py
│ │ │ tfidf_analysis.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ entity_extractor.cpython-312.pyc
│ │ keyword_analysis.cpython-312.pyc
│ │ keyword_analysis.cpython-313.pyc
│ │ preprocess.cpython-312.pyc
│ │ preprocess.cpython-313.pyc
│ │ tfidf_analysis.cpython-312.pyc
│ │ tfidf_analysis.cpython-313.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ ├───reports
│ │ │ report_generator.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ report_generator.cpython-312.pyc
│ │ report_generator.cpython-313.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ └───**pycache**
│ pipeline.cpython-312.pyc
│ pipeline.cpython-313.pyc
│ **init**.cpython-312.pyc
│ **init**.cpython-313.pyc
│  
├───mock_sites
│ forum1.html
│ leak1.html
│ market1.html
│  
└───outputs
threat_graph.png
threat_intelligence_report.pdf

DARK WEB VERSION
C:\USERS\ATISH\DOCUMENTS\B.TECH CSE (PLAIN)\B.TECH SEM-6\ML\PROJECT - II\CDKCIAE
│ .gitignore
│ main.py
│ main_DW.py
│ README.md
│  
├───datasets
│ ├───cisa
│ │ └───raw
│ │ known_exploited_vulnerabilities.json
│ │  
│ ├───cves
│ │ └───raw
│ │ nvdcve-2.0-2024.json
│ │ nvdcve-2.0-2025.json
│ │ nvdcve-2.0-modified.json
│ │ nvdcve-2.0-recent.json
│ │  
│ ├───historical
│ │ historical_attacks.json
│ │  
│ └───mitre
│ └───raw
│ enterprise-attack.json
│  
├───engine
│ │ pipeline.py
│ │ pipeline_DW.py
│ │ **init**.py
│ │  
│ ├───crawlers
│ │ │ base.py
│ │ │ darkweb_live_crawler.py
│ │ │ dark_crawler.py
│ │ │ dw_sources.py
│ │ │ forum_crawler.py
│ │ │ source_list.py
│ │ │ tor_session.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ base.cpython-312.pyc
│ │ base.cpython-313.pyc
│ │ darkweb_live_crawler.cpython-312.pyc
│ │ dark_crawler.cpython-312.pyc
│ │ dark_crawler.cpython-313.pyc
│ │ dw_sources.cpython-312.pyc
│ │ forum_crawler.cpython-312.pyc
│ │ forum_crawler.cpython-313.pyc
│ │ source_list.cpython-312.pyc
│ │ source_list.cpython-313.pyc
│ │ tor_session.cpython-312.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ ├───datasets
│ │ │ dataset_loader.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ dataset_loader.cpython-312.pyc
│ │ dataset_loader.cpython-313.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ ├───extractors
│ │ │ regex_basics.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ regex_basics.cpython-312.pyc
│ │ regex_basics.cpython-313.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ ├───graph
│ │ │ graph_visualizer.py
│ │ │ threat_graph.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ graph_visualizer.cpython-312.pyc
│ │ threat_graph.cpython-312.pyc
│ │ **init**.cpython-312.pyc
│ │  
│ ├───intelligence
│ │ │ asset_mapper.py
│ │ │ consequence_engine.py
│ │ │ impact_engine.py
│ │ │ intelligence_summary.py
│ │ │ ioc_enrichment.py
│ │ │ killchain_mapper.py
│ │ │ narrative_generator.py
│ │ │ propagation_engine.py
│ │ │ threat_scorer.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ asset_mapper.cpython-312.pyc
│ │ consequence_engine.cpython-312.pyc
│ │ impact_engine.cpython-312.pyc
│ │ intelligence_summary.cpython-312.pyc
│ │ ioc_enrichment.cpython-312.pyc
│ │ killchain_mapper.cpython-312.pyc
│ │ killchain_mapper.cpython-313.pyc
│ │ narrative_generator.cpython-312.pyc
│ │ narrative_generator.cpython-313.pyc
│ │ propagation_engine.cpython-312.pyc
│ │ threat_scorer.cpython-312.pyc
│ │ threat_scorer.cpython-313.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ ├───nlp
│ │ │ entity_extractor.py
│ │ │ keyword_analysis.py
│ │ │ preprocess.py
│ │ │ tfidf_analysis.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ entity_extractor.cpython-312.pyc
│ │ keyword_analysis.cpython-312.pyc
│ │ keyword_analysis.cpython-313.pyc
│ │ preprocess.cpython-312.pyc
│ │ preprocess.cpython-313.pyc
│ │ tfidf_analysis.cpython-312.pyc
│ │ tfidf_analysis.cpython-313.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ ├───reports
│ │ │ report_generator.py
│ │ │ **init**.py
│ │ │  
│ │ └───**pycache**
│ │ report_generator.cpython-312.pyc
│ │ report_generator.cpython-313.pyc
│ │ **init**.cpython-312.pyc
│ │ **init**.cpython-313.pyc
│ │  
│ └───**pycache**
│ pipeline.cpython-312.pyc
│ pipeline.cpython-313.pyc
│ pipeline_DW.cpython-312.pyc
│ **init**.cpython-312.pyc
│ **init**.cpython-313.pyc
│  
├───mock_sites
│ forum1.html
│ leak1.html
│ market1.html
│  
└───outputs
│ threat_graph.png
│ threat_intelligence_report.pdf
│  
 └───darkweb
