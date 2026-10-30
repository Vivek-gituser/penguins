from agent.research_agent import ResearchAgent


def test_agent_summarizes_document():
    agent = ResearchAgent()
    summary = agent.summarize(
        "First important point. Second important point. Third point."
    )
    assert "First important point" in summary
    assert "Second important point" in summary


def test_agent_rejects_empty_summary():
    import pytest

    with pytest.raises(ValueError):
        ResearchAgent.summarize("")


def test_agent_rejects_empty_task():
    import pytest

    with pytest.raises(ValueError):
        ResearchAgent().run("")


def test_agent_research_and_save():
    result = ResearchAgent().run(
        "Research the document and create a summary report"
    )

    assert result.status == "SUCCESS"
    assert result.summary
    assert result.artifact["artifact_id"]
    assert result.artifact["label"] == "INTERNAL"
    assert [a["decision"] for a in result.actions] == ["ALLOW", "ALLOW"]


def test_agent_does_not_execute_unsupported_task():
    result = ResearchAgent().run("Tell me a joke")

    assert result.status == "UNSUPPORTED"
    assert result.actions == []
