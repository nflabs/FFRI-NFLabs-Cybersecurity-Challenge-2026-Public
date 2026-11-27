const form = document.querySelector("#answer-form");
const answerInput = document.querySelector("#answer");
const submitButton = document.querySelector("#submit-button");
const result = document.querySelector("#result");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const answer = answerInput.value.trim();

  result.className = "result";
  if (!answer) {
    result.textContent = "回答を入力してください。";
    result.classList.add("error");
    answerInput.focus();
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = "CHECKING";

  try {
    const response = await fetch("/photo-recovery/api/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ answer }),
    });
    const data = await response.json();
    result.textContent = data.message;
    result.classList.add(data.ok ? "success" : "error");
  } catch {
    result.textContent = "サーバーへ接続できません。しばらくしてから再試行してください。";
    result.classList.add("error");
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "SUBMIT";
  }
});
