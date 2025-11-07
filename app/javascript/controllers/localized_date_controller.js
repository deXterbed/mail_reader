import { Controller } from "@hotwired/stimulus"

// Connects to data-controller="localized-date"
export default class extends Controller {
  static values = {
    iso: String,
    fallback: String
  }

  connect() {
    const formatted = this.formattedValue()
    if (formatted) {
      this.element.textContent = formatted
    }
  }

  formattedValue() {
    if (!this.hasIsoValue) {
      return this.fallbackValue || null
    }

    const parsedDate = new Date(this.isoValue)
    if (Number.isNaN(parsedDate.getTime())) {
      return this.fallbackValue || null
    }

    try {
      return parsedDate.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
        hour12: true
      })
    } catch (error) {
      return this.fallbackValue || parsedDate.toString()
    }
  }
}
