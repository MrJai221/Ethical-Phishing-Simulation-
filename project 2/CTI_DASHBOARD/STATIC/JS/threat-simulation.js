// This file now dynamically generates random threat data for a more realistic simulation.

// Bounding boxes for major continental landmasses to ensure threats appear on land.
const landmassBoundingBoxes = [
    { name: 'North America', minLat: 24, maxLat: 71, minLon: -168, maxLon: -52 },
    { name: 'South America', minLat: -55, maxLat: 12, minLon: -81, maxLon: -34 },
    { name: 'Europe', minLat: 36, maxLat: 71, minLon: -24, maxLon: 69 },
    { name: 'Africa', minLat: -34, maxLat: 37, minLon: -17, maxLon: 51 },
    { name: 'Asia', minLat: -11, maxLat: 77, minLon: 26, maxLon: 180 },
    { name: 'Australia', minLat: -43, maxLat: -10, minLon: 113, maxLon: 153 },
    // A specific box for India and surrounding region for higher probability
    { name: 'Indian Subcontinent', minLat: 8, maxLat: 37, minLon: 68, maxLon: 97 }
];

/**
 * Generates a random number within a given range.
 * @param {number} min - The minimum value.
 * @param {number} max - The maximum value.
 * @returns {number} A random number between min and max.
 */
function getRandomInRange(min, max) {
    return Math.random() * (max - min) + min;
}

/**
 * Generates a new, random threat object with coordinates on a landmass.
 * @returns {object} A threat object with lat, lon, country, etc.
 */
function generateRandomThreat() {
    // Select a random landmass bounding box.
    // We can "weight" certain areas by adding them to the list multiple times.
    // For example, adding 'Asia' again would double its chance of being picked.
    const selectedBox = landmassBoundingBoxes[Math.floor(Math.random() * landmassBoundingBoxes.length)];

    // Generate random coordinates within the selected box.
    const randomLat = getRandomInRange(selectedBox.minLat, selectedBox.maxLat);
    const randomLon = getRandomInRange(selectedBox.minLon, selectedBox.maxLon);

    // Generate a random-looking IP address for visual flavor.
    const randomIp = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

    // Return a threat object compatible with our map plotting function.
    return {
        lat: randomLat,
        lon: randomLon,
        city: 'Unknown Anomaly', // Makes it feel more like a raw detection
        country: selectedBox.name, // The continent name
        indicator: randomIp
    };
}