# =============================================================
# Logistic Regression: Sito Hackerato vs Non Hackerato
# Versione 2: con variabili numeriche, binarie, categoriche
# =============================================================
# Variabili predittore:
#   NUMERICHE:
#     vulnerabilities  = numero di vulnerabilita' note
#     days_no_update   = giorni dall'ultimo update
#     monthly_visitors = visitatori mensili (in migliaia)
#
#   BINARIA:
#     has_waf          = ha un WAF? (0/1)
#
#   CATEGORICA (4 livelli):
#     sector           = finance / healthcare / retail / government
#
# Risposta:
#   hacked            = 1 se hackerato, 0 altrimenti
# =============================================================

set.seed(42)
n <- 500


# --- 1. Generare i dati ---

vulnerabilities  <- rpois(n, lambda = 5)
days_no_update   <- round(runif(n, min = 1, max = 365))
monthly_visitors <- round(rlnorm(n, meanlog = 3, sdlog = 1))
has_waf          <- rbinom(n, size = 1, prob = 0.4)

# Variabile categorica: settore
sectors <- c("finance", "healthcare", "retail", "government")
sector  <- sample(sectors, n, replace = TRUE,
                  prob = c(0.25, 0.25, 0.35, 0.15))

# Coefficienti "veri" per la simulazione
# Ogni settore ha un suo effetto di base sul rischio di hacking
sector_effect <- ifelse(sector == "finance",     0.5,
                 ifelse(sector == "healthcare",  0.8,
                 ifelse(sector == "government",  1.2,
                                                 0.0)))  # retail = baseline

linear_part <- -3 +
               0.4  * vulnerabilities +
               0.008 * days_no_update +
               0.01 * monthly_visitors -
               1.5  * has_waf +
               sector_effect

prob_hacked <- 1 / (1 + exp(-linear_part))
hacked      <- rbinom(n, size = 1, prob = prob_hacked)

# Dataframe finale
data <- data.frame(
  vulnerabilities  = vulnerabilities,
  days_no_update   = days_no_update,
  monthly_visitors = monthly_visitors,
  has_waf          = has_waf,
  sector           = factor(sector),   # <-- IMPORTANTE: factor!
  hacked           = hacked
)

# Ispezionare
str(data)
summary(data)
cat("\nSiti hackerati:", sum(data$hacked), "su", n, "\n")
cat("Distribuzione per settore:\n")
print(table(data$sector, data$hacked, dnn = c("Settore", "Hacked")))


# --- 2. Split train/test ---

set.seed(123)
train_idx <- sample(1:n, size = 0.7 * n)
train <- data[train_idx, ]
test  <- data[-train_idx, ]

cat("\nTraining set:", nrow(train), "siti\n")
cat("Test set:    ", nrow(test), "siti\n\n")


# --- 3. Fittare il modello sul training ---

model <- glm(hacked ~ vulnerabilities + days_no_update + monthly_visitors +
                      has_waf + sector,
             data = train,
             family = binomial)

summary(model)


# --- 4. Interpretazione dei coefficienti ---

coefs <- coef(model)
odds_ratios <- exp(coefs)

cat("\n--- Odds Ratios (exp dei coefficienti) ---\n")
print(round(odds_ratios, 3))

cat("\nInterpretazione:\n")
cat("- Ogni vulnerabilita' in piu' moltiplica le odds per",
    round(odds_ratios["vulnerabilities"], 2), "\n")
cat("- Avere un WAF moltiplica le odds per",
    round(odds_ratios["has_waf"], 2),
    "(riduzione del", round((1 - odds_ratios["has_waf"]) * 100), "%)\n")
cat("- Healthcare vs finance (baseline alfabetico): odds x",
    round(odds_ratios["sectorhealthcare"], 2), "\n")
cat("- Government vs finance: odds x",
    round(odds_ratios["sectorgovernment"], 2), "\n")
cat("- Retail vs finance: odds x",
    round(odds_ratios["sectorretail"], 2), "\n")


# --- 5. Predizioni sul test set ---

test_probs <- predict(model, newdata = test, type = "response")
test_pred  <- ifelse(test_probs > 0.5, 1, 0)

confusion <- table(Predicted = test_pred, Actual = test$hacked)
cat("\n--- Confusion matrix sul test set ---\n")
print(confusion)

accuracy <- sum(diag(confusion)) / sum(confusion)
cat("\nAccuracy sul test:", round(accuracy * 100, 1), "%\n")


# --- 6. Predizione su un nuovo sito ---

nuovo_sito <- data.frame(
  vulnerabilities  = 8,
  days_no_update   = 200,
  monthly_visitors = 50,
  has_waf          = 0,
  sector           = factor("government", levels = levels(data$sector))
)

prob <- predict(model, newdata = nuovo_sito, type = "response")
cat("\nNuovo sito governativo a rischio: P(hacked) =",
    round(prob, 3), "\n")


# --- 7. Cambiare la baseline del factor ---

# Default: R usa "finance" come baseline (ordine alfabetico)
# Se vuoi usare "retail" come riferimento:
data$sector_rel <- relevel(data$sector, ref = "retail")

model_rel <- glm(hacked ~ vulnerabilities + days_no_update +
                          monthly_visitors + has_waf + sector_rel,
                 data = data,
                 family = binomial)

cat("\n--- Coefficienti con retail come baseline ---\n")
print(round(coef(model_rel), 3))
# Ora finance, healthcare, government vengono confrontati con retail