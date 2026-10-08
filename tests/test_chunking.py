from wap.utils.llm import chunk_text


def test_chunk_text_does_not_return_single_giant_blob():
    text = ("paragraph\n\n" * 200) + ("x" * 5000)
    chunks = chunk_text(text, max_chars=1000, overlap=50, max_chunks=20)
    assert len(chunks) >= 2
    assert all(len(c[1]) <= 1200 for c in chunks)


def test_chunk_empty():
    assert chunk_text("", 100, 10, 5) == []