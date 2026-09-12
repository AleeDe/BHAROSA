import { Router } from "express";
import { analyzeUrlController } from "../controllers/url.controller.js";

const router = Router();

router.post("/analyze", analyzeUrlController);

export default router;
