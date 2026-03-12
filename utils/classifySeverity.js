function classifySeverity(diameter, segmentationPercentage) {
  let row = 0;
  let col = 0;

  // Kategorisasi berdasarkan persentase segmentasi
  if (segmentationPercentage < 10) row = 1;
  else if (segmentationPercentage >= 10 && segmentationPercentage < 25) row = 2;
  else if (segmentationPercentage >= 25) row = 3;

  // Kategorisasi berdasarkan diameter
  if (diameter < 20) col = 1;
  else if (diameter >= 20 && diameter < 45) col = 2;
  else if (diameter >= 45) col = 3;

  const matrix = {
    "1,1": "Rendah",
    "1,2": "Rendah",
    "1,3": "Sedang",
    "2,1": "Rendah",
    "2,2": "Sedang",
    "2,3": "Tinggi",
    "3,1": "Sedang",
    "3,2": "Tinggi",
    "3,3": "Tinggi",
  };

  const key = `${row},${col}`;
  return matrix[key] || "Tidak diketahui";
}

module.exports = classifySeverity;
