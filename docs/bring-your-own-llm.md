# Bring your own LLM

asteraskills uses **LangChain** chat models for tools and agents. You choose the provider and model via environment variables (and optionally a small YAML map). The codebase does not host or fine-tune models; it only needs credentials and model names you already have.

## Chat models (reasoning / tool-calling)

Configured on `Settings` (loaded from the repository `.env`):

| Variable | Purpose |
|----------|---------|
| `LLM_PROVIDER` | `openai` (default) or `anthropic` |
| `LLM_MODEL` | Default model id, e.g. `gpt-4o-mini` or `claude-3-5-sonnet-20241022` |
| `LLM_TEMPERATURE` | Float; many tools default to their own temperature when calling `get_llm()` |
| `OPENAI_API_KEY` | Required when `LLM_PROVIDER=openai` |
| `ANTHROPIC_API_KEY` | Required when `LLM_PROVIDER=anthropic` |

The factory is `asteraskills.core.llm.get_llm()`:

- Resolves `model` and `provider` from arguments, then from settings.
- Builds `ChatOpenAI` or `ChatAnthropic` with the matching API key from settings or the process environment.

Callers can pass explicit `model=` / `provider=` for experiments without changing global `.env`.

## Per-task models (`config/llm_models.yaml`)

If you create `config/llm_models.yaml` at the **repository root** (next to `app/`), `get_settings().get_llm_model_for_type(llm_type)` can return different models per logical type. The file is optional.

Example shape:

```yaml
default_model: gpt-4o-mini
models:
  CVE_ENRICH: gpt-4o
  ATTACK_MAP: gpt-4o-mini
```

Keys under `models` are matched in **upper case** in code. If a type is missing, `default_model` or `LLM_MODEL` is used.

## Embeddings (vector ingestion and semantic search)

Semantic tools and ingestion use LangChain embeddings. Defaults are controlled by:

| Variable | Purpose |
|----------|---------|
| `EMBEDDING_PROVIDER` | Currently oriented around OpenAI-style embeddings in tooling; default `openai` |
| `EMBEDDING_MODEL` | e.g. `text-embedding-3-small` |
| `OPENAI_API_KEY` | Used for OpenAI embeddings when that provider is selected |

If you use a different embedding stack, swap the embedding class in the ingestion/storage code paths that construct retrievers, or add a small adapter consistent with your org’s standard. The rest of the pipeline (Qdrant/Chroma collections, chunking) stays the same.

## Operational notes

- **No keys in git**: keep secrets in `.env` (ignored by default) or your secret manager; inject env vars in CI the same way.
- **Rate limits**: optional `NVD_API_KEY` and similar keys are documented in `app/asteraskills/config/settings.py` for upstream APIs, not for the LLM itself.
- **Offline / air-gapped**: tools that only call public HTTP APIs or databases will fail without network or data; swap in local models by pointing `get_llm()` at compatible LangChain wrappers your environment provides.
