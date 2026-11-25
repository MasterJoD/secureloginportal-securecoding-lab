/* SecurePortal front-end helpers.
   No inline scripts are used anywhere, so the strict Content-Security-Policy can block injected scripts.
   Text is inserted with textContent (never innerHTML) to stay XSS-safe.
   NOTE: client-side checks are only for convenience - the server re-validates everything. */

document.addEventListener("DOMContentLoaded", function () {

  // ---- Show / hide password buttons ----
  document.querySelectorAll(".toggle-password").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.dataset.target);
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
    });
  });

  // ---- Password strength meter (registration page) ----
  var pw = document.getElementById("password");
  var bar = document.getElementById("strength-bar");
  var rules = document.getElementById("password-rules");
  if (pw && bar && rules) {
    var tests = {
      length: function (v) { return v.length >= 8; },
      upper: function (v) { return /[A-Z]/.test(v); },
      lower: function (v) { return /[a-z]/.test(v); },
      number: function (v) { return /[0-9]/.test(v); },
      special: function (v) { return /[^A-Za-z0-9]/.test(v); }
    };
    var colors = ["bg-danger", "bg-danger", "bg-warning", "bg-info", "bg-primary", "bg-success"];

    pw.addEventListener("input", function () {
      var met = 0;
      rules.querySelectorAll("li").forEach(function (li) {
        var ok = tests[li.dataset.rule](pw.value);
        li.classList.toggle("met", ok);
        if (ok) { met++; }
      });
      bar.style.width = (pw.value ? (met / 5) * 100 : 0) + "%";
      colors.forEach(function (c) { bar.classList.remove(c); });
      bar.classList.add(colors[met]);
      checkConfirm();
    });
  }

  // ---- Confirm password feedback ----
  var confirmInput = document.getElementById("confirm_password");
  var feedback = document.getElementById("confirm-feedback");
  function checkConfirm() {
    if (!confirmInput || !feedback) { return; }
    if (!confirmInput.value) { feedback.textContent = ""; return; }
    var same = confirmInput.value === pw.value;
    feedback.textContent = same ? "Passwords match." : "Passwords do not match.";
    feedback.className = "form-text " + (same ? "text-success" : "text-danger");
  }
  if (confirmInput) { confirmInput.addEventListener("input", checkConfirm); }

  // ---- Admin: fill the "view student" modal ----
  var viewModal = document.getElementById("viewModal");
  if (viewModal) {
    viewModal.addEventListener("show.bs.modal", function (event) {
      var d = event.relatedTarget.dataset;
      document.getElementById("view-name").textContent = d.name;
      document.getElementById("view-sid").textContent = d.sid;
      document.getElementById("view-email").textContent = d.email;
      document.getElementById("view-phone").textContent = d.phone;
      document.getElementById("view-created").textContent = d.created;
    });
  }

  // ---- Admin: fill the delete confirmation modal ----
  var deleteModal = document.getElementById("deleteModal");
  if (deleteModal) {
    deleteModal.addEventListener("show.bs.modal", function (event) {
      var d = event.relatedTarget.dataset;
      document.getElementById("delete-name").textContent = d.name;
      document.getElementById("delete-form").setAttribute("action", d.action);
    });
  }
});
