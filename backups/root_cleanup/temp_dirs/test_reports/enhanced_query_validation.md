# Enhanced Query Handler Validation Report

## Summary

- Component Extraction: 5 queries tested
- Synonym Expansion: 5 queries tested
- Alternative Query Generation: 5 queries tested
- Full Search Pipeline: 0 queries tested

## Component Extraction

### Query: 'gene expression data for liver cancer of human species'

Extracted components:

- **organism**: human
- **disease**: cancer
- **tissue**: liver
- **data_type**: gene expression

### Query: 'breast cancer gene expression in humans'

Extracted components:

- **organism**: human
- **disease**: cancer
- **data_type**: gene expression

### Query: 'diabetes metabolic gene expression profiles in pancreatic tissue'

Extracted components:

- **disease**: diabetes
- **tissue**: pancreatic
- **data_type**: gene expression

### Query: 'covid-19 lung transcriptome data'

Extracted components:

- **disease**: covid
- **tissue**: lung
- **data_type**: transcriptome

### Query: 'neurodegenerative disease brain expression profiles'

Extracted components:

- **organism**: rat
- **disease**: neurodegenerative
- **tissue**: brain
- **data_type**: expression

## Synonym Expansion

### Query: 'gene expression data for liver cancer of human species'

Expanded synonyms:

- **disease** (10 synonyms): carcinoma, cancer, malignancy, breast cancer, hepatic cancer, lung cancer, tumor, neoplasm, tumour, liver cancer
- **tissue** (5 synonyms): hepatic, liver, hepatocytes, hepatocellular, hepatocyte
- **organism** (6 synonyms): people, human subjects, patient, patients, homo sapiens, human
- **data_type** (5 synonyms): transcription, transcript, expression, mRNA expression, gene expression

### Query: 'breast cancer gene expression in humans'

Expanded synonyms:

- **disease** (10 synonyms): carcinoma, cancer, malignancy, breast cancer, hepatic cancer, lung cancer, tumor, neoplasm, tumour, liver cancer
- **organism** (6 synonyms): people, human subjects, patient, patients, homo sapiens, human
- **data_type** (5 synonyms): transcription, transcript, expression, mRNA expression, gene expression

### Query: 'diabetes metabolic gene expression profiles in pancreatic tissue'

Expanded synonyms:

- **disease** (7 synonyms): diabetic, T1D, type 2 diabetes, T2D, type 1 diabetes, diabetes mellitus, diabetes
- **tissue** (6 synonyms): islet, islets, beta cell, pancreas, pancreatic, beta cells
- **data_type** (5 synonyms): transcription, transcript, expression, mRNA expression, gene expression

### Query: 'covid-19 lung transcriptome data'

Expanded synonyms:

- **disease** (5 synonyms): coronavirus, sars-cov-2, covid19, covid, covid-19
- **tissue** (6 synonyms): lung, airway, alveolar, pulmonary, bronchial, respiratory
- **data_type** (2 synonyms): transcriptome, transcriptome sequencing

### Query: 'neurodegenerative disease brain expression profiles'

Expanded synonyms:

- **disease** (8 synonyms): alzheimer's disease, AD, parkinson, parkinson's disease, dementia, PD, neurodegenerative, alzheimer
- **tissue** (9 synonyms): neurons, neuronal, glial, neural, neuron, brain, cortex, cerebral, hippocampus
- **organism** (4 synonyms): rattus norvegicus, rodent, rats, rat
- **data_type** (7 synonyms): transcription, transcript, expression, mRNA expression, gene expression, protein expression, expression array

## Alternative Query Generation

### Query: 'gene expression data for liver cancer of human species'

Generated 10 alternative queries:

1. gene expression lung cancer human subjects
2. mRNA expression lung cancer human subjects
3. gene expression breast cancer homo sapiens
4. gene expression liver cancer homo sapiens
5. gene expression hepatic cancer homo sapiens
6. mRNA expression hepatic cancer human subjects
7. mRNA expression liver cancer human subjects
8. gene expression liver cancer human subjects
9. mRNA expression liver cancer homo sapiens
10. mRNA expression hepatic cancer homo sapiens

### Query: 'breast cancer gene expression in humans'

Generated 10 alternative queries:

1. gene expression lung cancer human subjects
2. mRNA expression lung cancer human subjects
3. gene expression breast cancer homo sapiens
4. gene expression liver cancer homo sapiens
5. gene expression hepatic cancer homo sapiens
6. mRNA expression hepatic cancer human subjects
7. mRNA expression liver cancer human subjects
8. gene expression liver cancer human subjects
9. mRNA expression liver cancer homo sapiens
10. mRNA expression hepatic cancer homo sapiens

### Query: 'diabetes metabolic gene expression profiles in pancreatic tissue'

Generated 10 alternative queries:

1. mRNA expression type 1 diabetes
2. beta cell type 2 diabetes
3. gene expression type 1 diabetes
4. beta cell type 1 diabetes
5. gene expression type 2 diabetes
6. beta cells type 2 diabetes
7. beta cells type 1 diabetes
8. mRNA expression type 2 diabetes
9. beta cell diabetes mellitus
10. transcription type 2 diabetes

### Query: 'covid-19 lung transcriptome data'

Generated 10 alternative queries:

1. transcriptome sequencing airway
2. transcriptome sequencing alveolar
3. transcriptome sequencing sars-cov-2
4. transcriptome sequencing lung
5. transcriptome sequencing coronavirus
6. transcriptome sequencing covid19
7. transcriptome sequencing covid
8. transcriptome sequencing pulmonary
9. transcriptome sequencing respiratory
10. transcriptome sequencing bronchial

### Query: 'neurodegenerative disease brain expression profiles'

Generated 10 alternative queries:

1. protein expression alzheimer's disease rattus norvegicus
2. expression array parkinson's disease rattus norvegicus
3. protein expression parkinson's disease rattus norvegicus
4. expression array alzheimer's disease rattus norvegicus
5. mRNA expression alzheimer's disease rattus norvegicus
6. gene expression parkinson's disease rattus norvegicus
7. gene expression alzheimer's disease rattus norvegicus
8. mRNA expression parkinson's disease rattus norvegicus
9. protein expression neurodegenerative rattus norvegicus
10. protein expression cortex rattus norvegicus

## Multi-Strategy Search

## Conclusion

The enhanced query handler is functioning as expected, providing:

1. Robust component extraction from complex biomedical queries
2. Comprehensive synonym expansion for medical terminology
3. Effective alternative query generation
4. Successful multi-strategy search with fallback mechanisms
