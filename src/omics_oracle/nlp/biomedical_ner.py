"""
Enhanced biomedical named entity recognition for OmicsOracle.

This module provides advanced NER capabilities using SciSpaCy models
specifically designed for biomedical text processing.
"""

import logging
from typing import Any, Dict, List, Optional, Set

try:
    import spacy

    HAS_SPACY = True
except ImportError:
    HAS_SPACY = False

try:
    import scispacy  # noqa: F401

    HAS_SCISPACY = True
except ImportError:
    HAS_SCISPACY = False

from ..core.config import Config
from ..core.exceptions import ModelLoadError, NLPProcessingError

logger = logging.getLogger(__name__)


class BiomedicalNER:
    """
    Advanced biomedical named entity recognition using SciSpaCy.

    Provides entity linking and more sophisticated biomedical entity
    recognition compared to the basic PromptInterpreter.
    """

    def __init__(
        self, config: Optional[Config] = None, model_name: str = "auto"
    ):
        """
        Initialize the biomedical NER processor.

        Args:
            config: Configuration object
            model_name: SciSpaCy model name ('auto', 'en_core_sci_sm',
                       'en_core_sci_md')
        """
        self.config = config or Config()
        self.model_name = model_name
        self.nlp_model = None
        self._initialize_models()

    def _initialize_models(self) -> None:
        """Initialize biomedical NLP models."""
        if not HAS_SPACY:
            logger.error(
                "spaCy not available - install with: pip install spacy"
            )
            return

        if not HAS_SCISPACY:
            logger.warning(
                "SciSpaCy not available - falling back to standard spaCy"
            )

        try:
            if self.model_name == "auto":
                # Try to load the best available model
                models_to_try = [
                    "en_core_sci_md",  # Medium model (better performance)
                    "en_core_sci_sm",  # Small model (faster)
                    "en_core_web_sm",  # Standard spaCy fallback
                ]

                for model in models_to_try:
                    try:
                        self.nlp_model = spacy.load(model)
                        self.model_name = model
                        logger.info("Loaded model: %s", model)
                        break
                    except OSError:
                        continue

                if not self.nlp_model:
                    raise ModelLoadError("No suitable NLP models found")

            else:
                # Load specific model
                self.nlp_model = spacy.load(self.model_name)
                logger.info("Loaded model: %s", self.model_name)

        except OSError as e:
            logger.error("Failed to load biomedical NLP models: %s", str(e))
            raise ModelLoadError(
                "Biomedical NLP models not available. "
                "Install SciSpaCy models or standard spaCy models."
            ) from e

    def extract_biomedical_entities(
        self, text: str, include_entity_linking: bool = False
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract biomedical entities from text with enhanced categorization.

        Args:
            text: Input text to analyze
            include_entity_linking: Whether to include entity linking information

        Returns:
            Dictionary of categorized biomedical entities
        """
        if not self.nlp_model:
            raise NLPProcessingError("NLP model not initialized")

        try:
            doc = self.nlp_model(text)

            entities = {
                "genes": [],
                "proteins": [],
                "diseases": [],
                "chemicals": [],
                "organisms": [],
                "tissues": [],
                "cell_types": [],
                "anatomical": [],
                "phenotypes": [],
                "experimental_techniques": [],
                "general": [],
            }

            for ent in doc.ents:
                entity_info = {
                    "text": ent.text,
                    "label": ent.label_,
                    "start": ent.start_char,
                    "end": ent.end_char,
                    "confidence": getattr(ent, "_.confidence", 1.0),
                }

                # Add entity linking information if available and requested
                if include_entity_linking and hasattr(ent, "_.kb_id"):
                    entity_info["kb_id"] = ent._.kb_id

                # Enhanced categorization for biomedical entities
                entity_text_lower = ent.text.lower()

                if self._is_gene_entity(ent, entity_text_lower):
                    entities["genes"].append(entity_info)
                elif self._is_protein_entity(ent, entity_text_lower):
                    entities["proteins"].append(entity_info)
                elif self._is_disease_entity(ent, entity_text_lower):
                    entities["diseases"].append(entity_info)
                elif self._is_chemical_entity(ent, entity_text_lower):
                    entities["chemicals"].append(entity_info)
                elif self._is_organism_entity(ent, entity_text_lower):
                    entities["organisms"].append(entity_info)
                elif self._is_tissue_entity(ent, entity_text_lower):
                    entities["tissues"].append(entity_info)
                elif self._is_cell_type_entity(ent, entity_text_lower):
                    entities["cell_types"].append(entity_info)
                elif self._is_anatomical_entity(ent, entity_text_lower):
                    entities["anatomical"].append(entity_info)
                elif self._is_phenotype_entity(ent, entity_text_lower):
                    entities["phenotypes"].append(entity_info)
                elif self._is_experimental_technique(ent, entity_text_lower):
                    entities["experimental_techniques"].append(entity_info)
                else:
                    entities["general"].append(entity_info)

            return entities

        except Exception as e:
            logger.error("Error extracting biomedical entities: %s", str(e))
            raise NLPProcessingError(
                f"Failed to extract biomedical entities: {str(e)}"
            ) from e

    def _is_gene_entity(self, ent, text_lower: str) -> bool:
        """Check if entity represents a gene."""
        # Specific gene patterns first (highest priority)
        gene_patterns = {
            "brca1",
            "brca2",
            "tp53",
            "p53",
            "egfr",
            "her2",
            "myc",
            "ras",
            "pten",
            "apc",
        }

        # Explicit disease/organism exclusions
        if self._is_disease_pattern(text_lower) or self._is_organism_pattern(
            text_lower
        ):
            return False

        # Check specific gene patterns
        if text_lower in gene_patterns:
            return True

        # SciSpaCy GENE label only
        if ent.label_ == "GENE":
            return True

        # Short uppercase strings that are likely genes (but not diseases/organisms)
        return (
            len(text_lower) <= 8
            and text_lower.isupper()
            and len(text_lower) >= 2
        )

    def _is_disease_pattern(self, text_lower: str) -> bool:
        """Check if text matches disease patterns."""
        disease_keywords = {
            "cancer",
            "carcinoma",
            "tumor",
            "diabetes",
            "disease",
        }
        return any(keyword in text_lower for keyword in disease_keywords)

    def _is_organism_pattern(self, text_lower: str) -> bool:
        """Check if text matches organism patterns."""
        organism_keywords = {"human", "mouse", "rat", "sapiens", "musculus"}
        return any(keyword in text_lower for keyword in organism_keywords)

    def _is_protein_entity(self, ent, text_lower: str) -> bool:
        """Check if entity represents a protein."""
        protein_labels = {"PROTEIN"}
        protein_patterns = {
            "insulin",
            "hemoglobin",
            "collagen",
            "albumin",
            "immunoglobulin",
            "antibody",
        }

        return (
            ent.label_ in protein_labels
            or text_lower in protein_patterns
            or "protein" in text_lower
        )

    def _is_disease_entity(self, ent: Any, text_lower: str) -> bool:
        """Check if entity represents a disease."""
        disease_labels = {"DISEASE", "DISORDER", "SYMPTOM"}
        disease_patterns = {
            "cancer",
            "carcinoma",
            "tumor",
            "diabetes",
            "alzheimer",
            "parkinson",
            "hypertension",
            "asthma",
            "arthritis",
        }

        # Explicit exclusions for genes (highest priority)
        if text_lower in {"brca1", "brca2", "tp53", "p53", "egfr"}:
            return False

        return (
            ent.label_ in disease_labels
            or any(pattern in text_lower for pattern in disease_patterns)
            or text_lower.endswith("oma")
            or text_lower.endswith("itis")
        )

    def _is_chemical_entity(self, ent, text_lower: str) -> bool:
        """Check if entity represents a chemical compound."""
        chemical_labels = {"CHEMICAL", "DRUG", "SMALL_MOLECULE"}
        chemical_patterns = {
            "glucose",
            "insulin",
            "dopamine",
            "serotonin",
            "acetylcholine",
            "atp",
            "dna",
            "rna",
        }

        return (
            ent.label_ in chemical_labels
            or text_lower in chemical_patterns
            or text_lower.endswith("ase")  # Enzymes
            or text_lower.endswith("in")  # Many drugs/chemicals
        )

    def _is_organism_entity(self, ent: Any, text_lower: str) -> bool:
        """Check if entity represents an organism."""
        organism_labels = {"ORGANISM", "SPECIES", "TAXON"}
        organism_patterns = {
            "human",
            "mouse",
            "rat",
            "zebrafish",
            "drosophila",
            "c. elegans",
            "e. coli",
            "s. cerevisiae",
            "homo sapiens",
            "mus musculus",
        }

        # Explicit exclusions for diseases and genes
        if text_lower in {"cancer", "brca1", "brca2", "tp53", "diabetes"}:
            return False

        return (
            ent.label_ in organism_labels
            or text_lower in organism_patterns
            or any(pattern in text_lower for pattern in organism_patterns)
        )

    def _is_tissue_entity(self, ent, text_lower: str) -> bool:
        """Check if entity represents tissue or organ."""
        tissue_labels = {"TISSUE", "ORGAN", "ANATOMICAL_ENTITY"}
        tissue_patterns = {
            "brain",
            "heart",
            "liver",
            "kidney",
            "lung",
            "breast",
            "prostate",
            "muscle",
            "bone",
            "skin",
            "blood",
        }

        return (
            ent.label_ in tissue_labels
            or text_lower in tissue_patterns
            or any(pattern in text_lower for pattern in tissue_patterns)
        )

    def _is_cell_type_entity(self, ent, text_lower: str) -> bool:
        """Check if entity represents a cell type."""
        cell_labels = {"CELL", "CELL_TYPE", "CELL_LINE"}
        cell_patterns = {
            "neuron",
            "lymphocyte",
            "fibroblast",
            "hepatocyte",
            "t cell",
            "b cell",
            "stem cell",
            "macrophage",
        }

        return (
            ent.label_ in cell_labels
            or text_lower in cell_patterns
            or "cell" in text_lower
            or text_lower.endswith("cyte")
        )

    def _is_anatomical_entity(self, ent, text_lower: str) -> bool:
        """Check if entity represents anatomical structure."""
        anatomical_labels = {"ANATOMICAL_ENTITY", "ANATOMY"}
        anatomical_patterns = {
            "chromosome",
            "mitochondria",
            "nucleus",
            "membrane",
            "cytoplasm",
            "ribosome",
        }

        return (
            ent.label_ in anatomical_labels
            or text_lower in anatomical_patterns
            or any(pattern in text_lower for pattern in anatomical_patterns)
        )

    def _is_phenotype_entity(self, ent, text_lower: str) -> bool:
        """Check if entity represents a phenotype."""
        phenotype_labels = {"PHENOTYPE", "TRAIT"}
        phenotype_patterns = {
            "expression",
            "activity",
            "function",
            "regulation",
            "pathway",
            "signaling",
        }

        return (
            ent.label_ in phenotype_labels
            or text_lower in phenotype_patterns
            or any(pattern in text_lower for pattern in phenotype_patterns)
        )

    def _is_experimental_technique(
        self, ent, text_lower: str
    ) -> bool:  # noqa: ARG002
        """Check if entity represents an experimental technique."""
        technique_patterns = {
            "pcr",
            "qpcr",
            "rt-pcr",
            "western blot",
            "microarray",
            "rna-seq",
            "chip-seq",
            "proteomics",
            "genomics",
            "sequencing",
            "flow cytometry",
            "immunofluorescence",
        }

        return (
            text_lower in technique_patterns
            or any(pattern in text_lower for pattern in technique_patterns)
            or (text_lower.endswith("-seq") and len(text_lower) > 4)
        )

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model."""
        if not self.nlp_model:
            return {"status": "not_loaded", "model": None}

        return {
            "status": "loaded",
            "model_name": self.model_name,
            "model_version": self.nlp_model.meta.get("version", "unknown"),
            "language": self.nlp_model.meta.get("lang", "en"),
            "has_scispacy": HAS_SCISPACY,
            "has_spacy": HAS_SPACY,
            "pipeline_components": list(self.nlp_model.pipe_names),
        }

    def is_available(self) -> bool:
        """Check if biomedical NER is available."""
        return self.nlp_model is not None


class EnhancedBiologicalSynonymMapper:
    """
    Enhanced biological synonym mapper with expanded dictionaries.

    Provides comprehensive mapping of biological terms to synonyms
    and standard identifiers, with support for multiple databases.
    """

    def __init__(self) -> None:
        """Initialize the enhanced synonym mapper."""
        self._init_comprehensive_synonym_maps()

    def _init_comprehensive_synonym_maps(self) -> None:
        """Initialize comprehensive synonym mappings."""
        # Expanded gene synonyms
        self.gene_synonyms = {
            # Oncogenes and tumor suppressors
            "brca1": ["breast cancer 1", "brca-1", "brcaa1", "rcd1"],
            "brca2": ["breast cancer 2", "brca-2", "brcaa2", "fancd1"],
            "tp53": [
                "tumor protein p53",
                "p53",
                "tp-53",
                "li-fraumeni syndrome",
            ],
            "pten": [
                "phosphatase and tensin homolog",
                "pten1",
                "cowden syndrome 1",
            ],
            "apc": [
                "adenomatous polyposis coli",
                "apc1",
                "familial adenomatous polyposis",
            ],
            "myc": ["myelocytomatosis oncogene", "c-myc", "myc proto-oncogene"],
            "ras": ["rat sarcoma", "hras", "kras", "nras"],
            "egfr": [
                "epidermal growth factor receptor",
                "egf receptor",
                "erbb1",
            ],
            "her2": [
                "human epidermal growth factor receptor 2",
                "erbb2",
                "neu",
            ],
            "bcl2": ["b-cell lymphoma 2", "bcl-2", "apoptosis regulator bcl2"],
            # Additional important genes
            "vegf": ["vascular endothelial growth factor", "vegf-a"],
            "tgfb": ["transforming growth factor beta", "tgf-beta", "tgfb1"],
            "il1": ["interleukin 1", "interleukin-1", "il-1"],
            "tnf": ["tumor necrosis factor", "tnf-alpha", "tnfa"],
            "ifn": ["interferon", "ifn-alpha", "ifn-beta", "ifn-gamma"],
        }

        # Expanded disease synonyms
        self.disease_synonyms = {
            # Cancers
            "breast cancer": [
                "breast carcinoma",
                "mammary cancer",
                "bc",
                "invasive ductal carcinoma",
            ],
            "lung cancer": [
                "lung carcinoma",
                "pulmonary cancer",
                "lc",
                "non-small cell lung cancer",
                "nsclc",
            ],
            "prostate cancer": [
                "prostate carcinoma",
                "pca",
                "adenocarcinoma of prostate",
            ],
            "colorectal cancer": [
                "colon cancer",
                "rectal cancer",
                "crc",
                "colorectal carcinoma",
            ],
            # Neurological disorders
            "alzheimer": [
                "alzheimer's disease",
                "ad",
                "dementia",
                "alzheimer disease",
            ],
            "parkinson": [
                "parkinson's disease",
                "pd",
                "parkinson disease",
                "paralysis agitans",
            ],
            # Metabolic disorders
            "diabetes": [
                "diabetes mellitus",
                "dm",
                "type 1 diabetes",
                "type 2 diabetes",
                "t1d",
                "t2d",
            ],
            "obesity": ["overweight", "adiposity", "corpulence"],
            # Cardiovascular
            "hypertension": [
                "high blood pressure",
                "htn",
                "arterial hypertension",
            ],
            "atherosclerosis": [
                "arteriosclerosis",
                "coronary artery disease",
                "cad",
            ],
        }

        # Expanded organism synonyms
        self.organism_synonyms = {
            "human": ["homo sapiens", "h. sapiens", "hsa", "man"],
            "mouse": ["mus musculus", "m. musculus", "mmu", "laboratory mouse"],
            "rat": [
                "rattus norvegicus",
                "r. norvegicus",
                "rno",
                "laboratory rat",
            ],
            "zebrafish": ["danio rerio", "d. rerio", "dre", "zebra fish"],
            "fruit fly": [
                "drosophila melanogaster",
                "d. melanogaster",
                "dme",
                "drosophila",
            ],
            "nematode": [
                "caenorhabditis elegans",
                "c. elegans",
                "cel",
                "roundworm",
            ],
            "yeast": [
                "saccharomyces cerevisiae",
                "s. cerevisiae",
                "sce",
                "baker's yeast",
            ],
            "e. coli": ["escherichia coli", "e coli", "eco"],
            "arabidopsis": [
                "arabidopsis thaliana",
                "a. thaliana",
                "ath",
                "thale cress",
            ],
        }

        # Tissue and organ synonyms
        self.tissue_synonyms = {
            "brain": [
                "cerebrum",
                "cerebral tissue",
                "neural tissue",
                "nervous tissue",
            ],
            "heart": ["cardiac tissue", "myocardium", "cardiac muscle"],
            "liver": ["hepatic tissue", "hepatocytes"],
            "kidney": ["renal tissue", "nephrons"],
            "lung": ["pulmonary tissue", "respiratory tissue"],
            "muscle": ["skeletal muscle", "muscular tissue", "myocytes"],
            "blood": ["hematopoietic tissue", "blood cells", "plasma"],
            "bone": ["skeletal tissue", "osseous tissue", "osteocytes"],
            "skin": [
                "cutaneous tissue",
                "dermal tissue",
                "epidermis",
                "dermis",
            ],
        }

        # Cell type synonyms
        self.cell_type_synonyms = {
            "t cell": [
                "t lymphocyte",
                "t-cell",
                "helper t cell",
                "cytotoxic t cell",
            ],
            "b cell": ["b lymphocyte", "b-cell", "plasma cell"],
            "macrophage": ["phagocyte", "antigen-presenting cell", "apc"],
            "neuron": ["nerve cell", "neural cell"],
            "fibroblast": ["connective tissue cell"],
            "stem cell": [
                "progenitor cell",
                "undifferentiated cell",
                "embryonic stem cell",
                "esc",
            ],
            "endothelial cell": ["vascular endothelium", "blood vessel lining"],
        }

        # Experimental technique synonyms
        self.technique_synonyms = {
            "rna-seq": [
                "rna sequencing",
                "transcriptome sequencing",
                "whole transcriptome shotgun sequencing",
            ],
            "chip-seq": [
                "chromatin immunoprecipitation sequencing",
                "chip sequencing",
            ],
            "western blot": ["western blotting", "immunoblot", "protein blot"],
            "pcr": ["polymerase chain reaction", "amplification"],
            "qpcr": ["quantitative pcr", "real-time pcr", "rt-pcr"],
            "microarray": ["gene chip", "dna microarray", "expression array"],
            "flow cytometry": ["facs", "fluorescence-activated cell sorting"],
        }

    def get_synonyms(self, term: str, entity_type: str = "general") -> Set[str]:
        """
        Get comprehensive synonyms for a biological term.

        Args:
            term: Input term
            entity_type: Type of entity (gene, disease, organism, tissue, cell_type, technique)

        Returns:
            Set of synonyms including the original term
        """
        term_lower = term.lower()
        synonyms = {term}  # Include original term

        # Check specific category first
        category_map = {
            "gene": self.gene_synonyms,
            "disease": self.disease_synonyms,
            "organism": self.organism_synonyms,
            "tissue": self.tissue_synonyms,
            "cell_type": self.cell_type_synonyms,
            "technique": self.technique_synonyms,
        }

        if entity_type in category_map:
            synonym_dict = category_map[entity_type]
            # Check if term is a canonical term
            if term_lower in synonym_dict:
                synonyms.update(synonym_dict[term_lower])
            else:
                # Check if term is a synonym of any canonical term
                for canonical, synonym_list in synonym_dict.items():
                    if term_lower in synonym_list:
                        synonyms.add(canonical)
                        synonyms.update(synonym_list)
                        break
        else:
            # Check all categories if not found in specific category
            for synonym_dict in category_map.values():
                if term_lower in synonym_dict:
                    synonyms.update(synonym_dict[term_lower])
                    break
                else:
                    # Check if term is a synonym
                    for canonical, synonym_list in synonym_dict.items():
                        if term_lower in synonym_list:
                            synonyms.add(canonical)
                            synonyms.update(synonym_list)
                            break

        return synonyms

    def normalize_term(self, term: str, entity_type: str = "general") -> str:
        """
        Normalize a biological term to its standard form.

        Args:
            term: Input term
            entity_type: Type of entity

        Returns:
            Normalized term
        """
        term_lower = term.lower()

        # Check if term is a synonym and return the canonical form
        category_map = {
            "gene": self.gene_synonyms,
            "disease": self.disease_synonyms,
            "organism": self.organism_synonyms,
            "tissue": self.tissue_synonyms,
            "cell_type": self.cell_type_synonyms,
            "technique": self.technique_synonyms,
        }

        if entity_type in category_map:
            for canonical, synonyms in category_map[entity_type].items():
                if term_lower in synonyms or term_lower == canonical:
                    if entity_type == "gene":
                        return canonical.upper()
                    else:
                        return canonical.title()

        # Return original term if no normalization found
        return term

    def get_entity_relationships(self, term: str) -> Dict[str, List[str]]:
        """
        Get related entities for a given term.

        This is a basic implementation that could be expanded with
        knowledge graphs or external databases.

        Args:
            term: Input term

        Returns:
            Dictionary of related entities by type
        """
        term_lower = term.lower()
        relationships = {
            "related_genes": [],
            "related_diseases": [],
            "related_organisms": [],
            "related_techniques": [],
        }

        # Basic relationship mapping (could be expanded significantly)
        if term_lower in ["brca1", "brca2"]:
            relationships["related_diseases"] = [
                "breast cancer",
                "ovarian cancer",
            ]
            relationships["related_techniques"] = [
                "sequencing",
                "genetic testing",
            ]

        elif term_lower in ["tp53", "p53"]:
            relationships["related_diseases"] = [
                "li-fraumeni syndrome",
                "various cancers",
            ]
            relationships["related_genes"] = ["mdm2", "p21"]

        elif "cancer" in term_lower:
            relationships["related_techniques"] = [
                "rna-seq",
                "chip-seq",
                "immunohistochemistry",
            ]
            relationships["related_genes"] = [
                "tp53",
                "brca1",
                "brca2",
                "pten",
                "apc",
            ]

        return relationships
