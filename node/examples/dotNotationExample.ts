// Dot-notation — precise control over nested data structures.

import { shield } from "../src/index.js";

const PATIENT_RECORD = {
  name: "Charlie Davis",
  age: 42,
  contact: {
    email: "charlie@example.com",
    phone: "+1-555-0200",
    emergency: { name: "Diana Davis", phone: "+1-555-0201" },
  },
  medical: {
    blood_type: "O+",
    allergies: ["penicillin"],
    diagnosis: "Type 2 diabetes",
    prescriptions: ["metformin"],
  },
};

// Scheduling agent sees name and contact info only — no medical data.
const getForScheduling = shield({
  purpose: "scheduling",
  scope: ["name", "contact.email", "contact.phone"],
})((_patientId: string) => PATIENT_RECORD);

// Pharmacy agent sees allergies and prescriptions — no diagnosis or contact.
const getForPharmacy = shield({
  purpose: "pharmacy",
  scope: ["name", "medical.allergies", "medical.prescriptions"],
})((_patientId: string) => PATIENT_RECORD);

// Nurse sees everything except diagnosis (need doctor authorization).
const getForNurse = shield({
  purpose: "nurse",
  denyFields: ["medical.diagnosis"],
})((_patientId: string) => PATIENT_RECORD);

console.log("Scheduling agent sees:");
console.log(getForScheduling("P-001"));

console.log("\nPharmacy agent sees:");
console.log(getForPharmacy("P-001"));

console.log("\nNurse agent sees:");
console.log(getForNurse("P-001"));
