import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3333;
const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_super_segura_doc_cutias';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
    (req as any).user = user;
    next();
  });
};

app.post('/api/auth/login', async (req: Request, res: Response): Promise<any> => {
  const { username, password } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: { username: username.toLowerCase() }
    });

    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const token = jwt.sign(
      { 
        id: user.id, 
        role: user.role, 
        department: user.department, 
        municipality: user.municipality 
      }, 
      JWT_SECRET, 
      { expiresIn: '8h' }
    );

    const { password: _, ...userWithoutPassword } = user;
    res.json({ token, user: userWithoutPassword });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.get('/api/documents', authenticateToken, async (req: Request, res: Response) => {
  try {
    const documents = await prisma.document.findMany({
      include: {
        history: true,
        signatures: true
      },
      orderBy: { createdAt: 'desc' }
    });
    res.json(documents);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar documentos.' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor DOC rodando na porta ${PORT}`);
});
// Rota para criar um novo documento/ofício
app.post('/api/documents', authenticateToken, async (req: Request, res: Response): Promise<any> => {
  const {
    protocol,
    title,
    type,
    origin,
    destination,
    description,
    deadlineDate,
    priority,
    status,
    municipality,
    attachment
  } = req.body;

  try {
    const newDocument = await prisma.document.create({
      data: {
        protocol,
        title,
        type,
        origin,
        destination,
        description,
        deadlineDate: new Date(deadlineDate),
        priority,
        status,
        municipality: municipality || 'Cutias',
        attachmentName: attachment?.name,
        attachmentType: attachment?.type,
        attachmentSize: attachment?.size,
        attachmentData: attachment?.data,
        history: {
          create: [
            {
              user: (req as any).user ? `${(req as any).user.department}` : 'Sistema',
              action: 'Documento PROTOCOLADO',
              notes: 'Envio efetuado via Portal de Documentação integrado.'
            }
          ]
        }
      },
      include: {
        history: true,
        signatures: true
      }
    });

    res.status(201).json(newDocument);
  } catch (error) {
    console.error('Erro ao criar documento:', error);
    res.status(500).json({ error: 'Erro ao salvar o documento no banco de dados.' });
  }
});
// Rota para atualizar um documento (despachos, mudança de status, dilação de prazo, etc.)
app.put('/api/documents/:id', authenticateToken, async (req: Request, res: Response): Promise<any> => {
  const { id } = req.params;
  const {
    status,
    deadlineDate,
    response,
    historyItem
  } = req.body;

  try {
    // Prepara os dados de atualização dinamicamente
    const updateData: any = {};
    if (status) updateData.status = status;
    if (deadlineDate) updateData.deadlineDate = new Date(deadlineDate);
    
    // Se houver dados de resposta/despacho final
    if (response) {
      updateData.responseUser = response.responder;
      updateData.responseText = response.text;
      updateData.responseDate = new Date(response.createdAt);
    }

    // Se houver um novo item de histórico para registrar na trilha de auditoria
    if (historyItem) {
      updateData.history = {
        create: [
          {
            user: historyItem.user,
            action: historyItem.action,
            notes: historyItem.notes
          }
        ]
      };
    }

    const updatedDocument = await prisma.document.update({
      where: { id },
      data: updateData,
      include: {
        history: true,
        signatures: true
      }
    });

    res.json(updatedDocument);
  } catch (error) {
    console.error('Erro ao atualizar documento:', error);
    res.status(500).json({ error: 'Erro ao atualizar o documento no banco de dados.' });
  }
});